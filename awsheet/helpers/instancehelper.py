from ..core import AWSHeet
from .awshelper import AWSHelper
from .nicknamehelper import NickNameHelper
import time
import re
import os
import json
import subprocess
import tempfile
import argparse
import sys
import logging
import atexit
import boto
import boto.ec2
import boto.ec2.elb
import boto.cloudformation
import boto.vpc

class InstanceHelper(AWSHelper):
    "modular and convergent ec2 instances"
    def __init__(self, heet, role, **kwargs):
        self.heet = heet
        self.role = role
        self.environment = heet.get_value('environment', kwargs, default=heet.get_environment())
        self.kwargs = kwargs
        self.ami = heet.get_value('ami', kwargs)
        self.pv_ami = heet.get_value('pv_ami', kwargs)
        self.hvm_ami = heet.get_value('hvm_ami', kwargs)
        self.key_name = heet.get_value('key_name', kwargs)
        self.instance_type = heet.get_value('instance_type', kwargs, default='t1.micro')
        # if instance does not support pv ami, use the default hvm_ami if defined
        if not self.supports_pv() and not self.hvm_ami is None:
            self.heet.logger.debug("using hvm_ami %s because %s instances require hvm" %
                                   (self.hvm_ami, self.instance_type))
            self.ami = self.hvm_ami
        # if self.ami is not defined (by default or via parameter), use the default pv_ami if defined
        if self.ami is None and not self.pv_ami is None:
            self.ami = self.pv_ami
        self.version = heet.get_value('version', kwargs, default=heet.get_version())
        self.index = heet.get_value('index', kwargs, default=InstanceHelper.get_count_of_role(role))
        # if subnets is provided as a list, pick a round-robin subnet_id
        self.subnets = heet.get_value('subnets', kwargs, default=[])
        if (isinstance(self.subnets, list) and len(self.subnets) > 0):
            # self.index is one-based so subtract one to get zero-based
            default_subnet_id = self.subnets[(self.index - 1) % len(self.subnets)]
        else:
            default_subnet_id = None
        self.subnet_id = heet.get_value('subnet_id', kwargs, default=default_subnet_id)
        # combine base_security_groups from heet defaults and security_groups from kwargs
        self.base_security_groups = heet.get_value('base_security_groups', default=[])
        self.security_groups = heet.get_value('security_groups', kwargs, default=[])
        self.security_groups.extend(self.base_security_groups)
        user_data = heet.get_value('user_data', kwargs)
        self.user_data = json.dumps(user_data) if type(user_data) == dict else user_data
        self.conn = boto.ec2.connect_to_region(
            heet.get_region(),
            aws_access_key_id=heet.access_key_id,
            aws_secret_access_key=heet.secret_access_key)
        self.vpc_conn = boto.vpc.connect_to_region(
            heet.get_region(),
            aws_access_key_id=heet.access_key_id,
            aws_secret_access_key=heet.secret_access_key)
        self.public = heet.get_value('associate_public_ip_address', kwargs, default=self.is_subnet_public(self.subnet_id))

        # need unique way of identifying the instance based upon the inputs of this class (i.e. not the EC2 instance-id)
        #self.unique_tag = '%s__%s__v%s__i%s' % (self.role, self.environment, self.version, self.index)
        self.unique_tag = '%s/%s/v=%s/%s/%s/index=%s/%s' % (self.heet.base_name, self.environment, self.version, self.ami, self.instance_type, self.index, self.role)
        # call post_init_hook before add_resource/converge
        self.post_init_hook()
        heet.add_resource(self)

    def __str__(self):
        return "Instance %s" % self.unique_tag

    def get_resource_object(self):
        """return boto object for existing resource or None of doesn't exist. the response is not cached"""
        for instance in self.conn.get_only_instances(filters={'tag:'+AWSHeet.TAG:self.unique_tag}):
            if instance.state == 'pending' or instance.state == 'running':
                return instance
        return None

    def get_instance(self):
        """cached copy of get_resource_object()"""
        if not hasattr(self, 'instance') or self.instance is None:
            self.instance = self.get_resource_object()
        return self.instance

    def find_key_name(self):
        """returns first Key Pair returned by api. This is just a guess that should work for some people if no key pair is specified"""
        key_pairs = self.conn.get_all_key_pairs()
        if len(key_pairs) == 0:
            raise Exception("your AWS account must have at least one Key Pair https://console.aws.amazon.com/ec2/v2/home?region=us-east-1#KeyPairs:")
        return key_pairs[0].name

    def provision_resource(self):
        """ask EC2 for a new instance and return boto ec2 instance object"""

        self.heet.logger.info("provisioning ec2 instance type %s for role=%s and environment=%s" % (self.instance_type, self.role, self.environment))

        if (self.key_name is None):
            self.key_name = self.find_key_name()
            self.heet.logger.debug("no key_name was provided, so use the first Key Pair from api: '%s'" % self.key_name)

        run_kwargs = {
            # only supporting 1 instance per reservation / helper
            'min_count' : 1,
            'max_count' : 1,
            'key_name' : self.key_name,
            'user_data' : self.user_data,
            'instance_type' : self.instance_type
            }

        # pass in any possibly argument to run_instances based on constructor args and heet defaults
        for arg in [
            'addressing_type', 'placement', 'kernel_id', 'ramdisk_id', 'monitoring_enabled',
            'block_device_map', 'disable_api_termination', 'instance_initiated_shutdown_behavior',
            'private_ip_address', 'placement_group', 'client_token', 'additional_info',
            'instance_profile_name', 'instance_profile_arn', 'tenancy', 'ebs_optimized', 'dry_run'
            ]:
            run_kwargs[arg] = self.heet.get_value(arg, kwargs=self.kwargs)

        if self.subnet_id:
            # AWS expect security group *ids* when calling via this technique
            # create network interface with security_groups and public ip address
            interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(
                subnet_id=self.subnet_id,
                groups=self.security_groups,
                associate_public_ip_address=self.public
                )
            interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(interface)
            run_kwargs['network_interfaces'] = interfaces
        else:
            # AWS expect security groups *names* when calling via this technique
            run_kwargs['security_groups'] = self.security_groups

        #run_kwargs['dry_run'] = True
        reservation = self.conn.run_instances(self.ami, **run_kwargs)
        return reservation.instances[0]

    def wait_unil_ready(self):
        while True:
            try:
                self.instance.update()
                if self.instance.state != "pending":
                    break
                self.heet.logger.debug("%s state=%s" % (self.instance, self.instance.state))
            except boto.exception.EC2ResponseError as e:
                self.heet.logger.debug("waiting for instance %s" % self.instance)
            time.sleep(3)

    def converge(self):
        if not self.get_instance():
            self.instance = self.provision_resource()
            self.wait_unil_ready()
        self.set_tag(AWSHeet.TAG, self.unique_tag)
        self.set_tag('Name', self.get_name())
        if self.get_dnsname():
            NickNameHelper(self.heet, self.get_dnsname(), self)
        if self.get_index_dnsname():
            NickNameHelper(self.heet, self.get_index_dnsname(), self)
        self.post_converge_hook()
        name = self.get_dnsname()
        if not name:
            name = self.get_instance().public_dns_name
        if not name:
            name = self.get_instance().ip_address
        self.heet.logger.info("the following instance is ready '%s'" % name)
        return self

    def destroy(self):
        # TODO consider deleting all CNAMEs that point to public dns name
        instance = self.get_instance()
        if not instance:
            return
        self.pre_destroy_hook()
        if self.get_dnsname():
            NickNameHelper(self.heet, self.get_dnsname(), self).destroy()
        if self.get_index_dnsname():
            NickNameHelper(self.heet, self.get_index_dnsname(), self).destroy()
        self.heet.logger.info("terminating %s" % instance)
        self.conn.terminate_instances([instance.id])

    def get_cname_target(self):
        """returns public_dns_name"""
        if self.public:
            return self.get_instance().public_dns_name
        else:
            return self.get_instance().private_ip_address

    def get_basename(self):
        """returns a base name, usually a combination of role and environment"""
        str = '%s-%s' % (self.environment, self.role)
        return re.sub('[^A-z0-9\-]', '-', str)

    def get_name(self):
        """returns a unique host name, usually a combination of role and environment and something unique about the instance. When converging, an Name tag is created with this value"""
        if self.get_instance():
            octets = self.get_instance().private_ip_address.split('.')
        else:
            octets = '0.0.0.0'.split('.')
        return '%s-%s-%s-%s-%s' % (self.get_basename(), octets[0], octets[1], octets[2], octets[3])

    def get_dnsname(self):
        """returns a unique dns name based on get_name()/get_basename() including domain. Return None when no domain provided or other exception"""
        try:
            return self.get_name() + self.heet.get_value('domain', required=True)
        except:
            return None

    def get_index_dnsname(self):
        """returns a unique dns name based on instance get_basename() and index including domain. Return None when no domain provided or other exception"""
        try:
            return "%s-%02d%s" % (self.get_basename(), self.index, self.heet.get_value('domain', required=True))
        except:
            return None

    def set_tag(self, key, value):
        """add tag to the instance. This operation is idempotent. Tags are automatically destroyed when instances are terminated"""
        instance = self.get_instance()
        if key in instance.tags and instance.tags[key] == value:
            return
        self.heet.logger.debug("setting tag %s=%s on instance %s" % (key, value, instance))
        instance.add_tag(key, value)

    # cache whether or not a subnet is public or private
    subnet_public = {}

    def is_subnet_public(self, subnet_id):
        """returns true if the Subnet is associated with a Route Table with a default route to an Internet Gateway"""

        # cache whether or not a subnet is public or private
        if subnet_id in InstanceHelper.subnet_public:
            return InstanceHelper.subnet_public[subnet_id]

        # get the route table associated with this subnet (or the default/main route table)
        route_tables = self.vpc_conn.get_all_route_tables(None, filters={'association.subnet-id': subnet_id})
        if len(route_tables) == 0:
            route_tables = self.vpc_conn.get_all_route_tables(None, filters={'association.main': 'true' })
        route_table = route_tables[0]

        # find the default route in the table and see if it points at an internet gateway
        public = False
        for r in route_table.routes:
            if r.destination_cidr_block == '0.0.0.0/0' and r.gateway_id and re.match('^igw-', r.gateway_id):
                public = True

        InstanceHelper.subnet_public[subnet_id] = public
        return public

    role_counts = {}
    @classmethod
    def get_count_of_role(cls, role):
        """Return count of instances with this role. First invocation returns 1, second returns 2, etc."""
        current_count = cls.role_counts[role] if role in cls.role_counts else 0
        current_count += 1
        cls.role_counts[role] = current_count
        return current_count

    def supports_pv(self):
        """Return True when self.instance_type can boot from paravirtual EBS image (not HVM)
        http://aws.amazon.com/amazon-linux-ami/instance-type-matrix/"""
        return not re.search('^(i2|cc2|g2|cg1)\.', self.instance_type)

