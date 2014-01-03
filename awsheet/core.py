#!/usr/bin/python

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

class AWSHeet:

    TAG = 'AWSHeet'

    def __init__(self, defaults={}):
        self.defaults = defaults
        self.resources = []
        self.parse_args()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(sys.stdout)
        #handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.base_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        self.base_name = re.search('(.*)\.[^\.]*$', os.path.basename(sys.argv[0])).group(1)
        self.load_creds()
        atexit.register(self._finalize)

    def load_creds(self):
        """Load credentials in preferred order 1) from x.auth file 2) from environmental vars or 3) from ~/.boto config"""

        user_boto_config = os.path.join(os.environ.get('HOME'), ".boto")
        self.parse_creds_from_file(user_boto_config)

        self.access_key_id = os.getenv('AWS_ACCESS_KEY_ID', None)
        self.secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY', None)

        auth_file = os.path.join(self.base_dir, self.base_name + ".auth")
        self.parse_creds_from_file(auth_file)

        self.logger.debug("using account AWS_ACCESS_KEY_ID=%s" % self.access_key_id)

    def parse_creds_from_file(self, filename):
        if not os.path.exists(filename):
            return
        with open(filename) as f:
            for line in f:
                match = re.match('^[^#]*AWS_ACCESS_KEY_ID\s*=\s*(\S+)', line, re.IGNORECASE)
                if match:
                    self.access_key_id = match.group(1)
                match = re.match('^[^#]*AWS_SECRET_ACCESS_KEY\s*=\s*(\S+)', line, re.IGNORECASE)
                if match:
                    self.secret_access_key = match.group(1)

    def add_resource(self, resource):
        self.resources.append(resource)
        if not self.args.destroy:
            resource.converge()
        return resource

    def _finalize(self):
        """Run this function automatically atexit. If --destroy flag is use, destroy all resouces in reverse order"""
        if not self.args.destroy:
            return
        sys.stdout.write("You have asked to destroy the following resources from the '%s' environment:\n%s\n" % (self.args.environment, self.resources))
        sys.stdout.write("Are you sure? y/N: ")
        choice = raw_input().lower()
        if choice != 'y':
            print "Abort - not destroying resources without affirmation"
            exit(1)
        for resource in reversed(self.resources):
            print "destroying %s resource" % resource
            resource.destroy()

    def parse_args(self):
        parser = argparse.ArgumentParser(description='create and destroy AWS resources idempotently')
        parser.add_argument('-d', '--destroy', help='release the resources (terminate instances, delete stacks, etc)', action='store_true')
        parser.add_argument('-e', '--environment', help='e.g. production, staging, testing, etc', default='testing')
        parser.add_argument('-v', '--version', help='create/destroy resources associated with a version to support having multiple versions of resources running at the same time. Some resources are not possibly able to support versions - such as CNAMEs without a version string.')
        #parser.add_argument('-n', '--dry-run', help='environment', action='store_true')
        self.args = parser.parse_args()

    def get_version(self):
        return self.args.version if self.args.version else 0

    def get_environment(self):
        return self.args.environment

    def get_value(self, name, kwargs={}, default=None, required=True):
        """return first existing value from 1) kwargs dict params 2) global heet defaults 3) default param or 4) return None"""
        if (name in kwargs):
            return kwargs[name]
        if (name in self.defaults):
            return self.defaults[name]
        if (default != None):
            return default
        if required:
            raise Exception("You are missing a required argument or default value for '%s'." % (name))
        return None

    def exec_awscli(self, cmd):
        env = os.environ.copy()
        env['AWS_ACCESS_KEY_ID'] = self.access_key_id
        env['AWS_SECRET_ACCESS_KEY'] = self.secret_access_key
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, env=env)
        return proc.communicate()[0]

    def add_instance_to_elb(self, defaults, elb_name, instance_helper):
        if self.args.destroy:
            return
        conn = boto.ec2.elb.connect_to_region(
            defaults['region'],
            aws_access_key_id=self.access_key_id,
            aws_secret_access_key=self.secret_access_key)
        lb = conn.get_all_load_balancers(load_balancer_names=[elb_name])[0]
        instance_id = instance_helper.get_instance().id
        self.logger.info("register instance %s on %s" % (instance_id, elb_name))
        lb.register_instances(instance_id)

class AWSHelper(object):
    "modular and convergent AWS Resources superclass"

    def post_init_hook(self):
        self.heet.logger.debug("no defined method post_init_hook for %s" % self)

    def post_converge_hook(self):
        self.heet.logger.debug("no defined method post_converge_hook for %s" % self)

    def pre_destroy_hook(self):
        self.heet.logger.debug("no defined method pre_destroy_hook for %s" % self)

    def get_cname_target(self):
        raise Exception("no cname target defined for %s" % self)

class CloudFormationHelper(AWSHelper):
    "modular and convergent AWS CloudFormation"

    DOES_NOT_EXIST = 'DOES NOT EXIST'

    def __init__(self, heet, **kwargs):
        self.heet = heet
        self.stack_base_name = heet.get_value('stack_base_name', kwargs)
        self.environment = heet.get_value('environment', kwargs, default=heet.get_environment())
        self.template_file_name = heet.get_value('template_file_name', kwargs)
        self.template = open(self.template_file_name, 'r').read();
        self.version = heet.get_value('version', kwargs, default=heet.get_version())
        self.conn = boto.cloudformation.connect_to_region(
            self.heet.get_value('region'),
            aws_access_key_id=heet.access_key_id,
            aws_secret_access_key=heet.secret_access_key)
        heet.add_resource(self)

    def stack_name(self):
        if self.version:
            return self.stack_base_name + '-' + self.environment + '-v' + self.version
        else:
            return self.stack_base_name + '-' + self.environment

    def describe(self):
        try:
            return self.conn.describe_stacks(self.stack_name())[0]
        except boto.exception.BotoServerError:
            return None

    def status(self):
        stack = self.describe()
        if stack == None:
            return CloudFormationHelper.DOES_NOT_EXIST
        else:
            return stack.stack_status

    def get_output(self, key, default=''):
        stack = self.describe()
        if stack == None:
            return default
        for output in stack.outputs:
            if output.key == key:
                return output.value
        return default

    def create(self):
        self.heet.logger.info("creating CloudFormation stack '%s'" % self.stack_name())
        self.conn.create_stack(self.stack_name(), self.template, None)

    def update(self):
        try:
            self.heet.logger.info("updating CloudFormation stack '%s'" % self.stack_name())
            self.conn.update_stack(self.stack_name(), self.template)
        except boto.exception.BotoServerError as e:
            # noop update results in 400
            return

    def create_or_update(self):
        self.conn.validate_template(self.template)
        status = self.status()
        if status == 'DELETE_IN_PROGRESS':
            raise Exception("existing stack '%s' is currently being deleted" % self.stack_name())
        if status == 'DELETE_FAILED':
            raise Exception("delete of stack '%s' failed" % self.stack_name())
        if status == CloudFormationHelper.DOES_NOT_EXIST:
            self.create()
        else:
            self.update()

    def wait_for_complete(self):
        while(True):
            status = self.status()
            self.heet.logger.debug("CloudFormation stack '%s' status: %s" % (self.stack_name(), status))
            if re.search('COMPLETE', status):
                break
            if status == CloudFormationHelper.DOES_NOT_EXIST:
                break
            time.sleep(2)

    def converge(self):
        self.create_or_update()
        self.wait_for_complete()

    def destroy(self):
        status = self.status()
        if status == CloudFormationHelper.DOES_NOT_EXIST:
            return
        self.heet.logger.info("deleting CloudFormation stack '%s'" % self.stack_name())
        self.conn.delete_stack(self.stack_name())
        self.wait_for_complete()


class InstanceHelper(AWSHelper):
    "modular and convergent ec2 instances"
    def __init__(self, heet, role, **kwargs):
        self.heet = heet
        self.role = role
        self.environment = heet.get_value('environment', kwargs, default=heet.get_environment())
        self.ami = heet.get_value('ami', kwargs)
        self.key_name = heet.get_value('key_name', kwargs)
        self.instance_type = heet.get_value('instance_type', kwargs, default='t1.micro')
        self.version = heet.get_value('version', kwargs, default=heet.get_version())
        self.subnet_id = heet.get_value('subnet_id', kwargs, required=False)
        self.index = heet.get_value('index', kwargs, required=False)
        # combine base_security_groups from heet defaults and security_groups from kwargs
        self.base_security_groups = heet.get_value('base_security_groups', default=[])
        self.security_groups = heet.get_value('security_groups', kwargs, default=[])
        self.security_groups.extend(self.base_security_groups)
        user_data = heet.get_value('user_data', kwargs, required=False)
        self.user_data = json.dumps(user_data) if type(user_data) == dict else user_data
        self.conn = boto.ec2.connect_to_region(
            heet.get_value('region'),
            aws_access_key_id=heet.access_key_id,
            aws_secret_access_key=heet.secret_access_key)
        # need unique way of identifying the instance based upon the inputs of this class (i.e. not the EC2 instance-id)
        self.unique_tag = '%s__%s__v%s__i%s' % (self.role, self.environment, self.version, self.index)
        # call post_init_hook before add_resource/converge
        self.post_init_hook()
        heet.add_resource(self)

    def get_resource_object(self):
        """return boto object for existing resource or None of doesn't exist. the response is not cached"""
        for instance in self.conn.get_only_instances(filters={'tag:'+AWSHeet.TAG:self.unique_tag}):
            if instance.state != 'terminated':
                return instance
        return None

    def get_instance(self):
        """cached copy of get_resource_object()"""
        if not hasattr(self, 'instance') or self.instance == None:
            self.instance = self.get_resource_object()
        return self.instance

    def provision_resource(self):
        """ask EC2 for a new instance and return boto ec2 instance object"""
        # only tested with vpc-style accounts
        # only supporting 1 instance per reservation / helper

        kwargs = {
            'min_count' : 1,
            'max_count' : 1,
            'key_name' : self.key_name,
            'user_data' : self.user_data,
            'instance_type' : self.instance_type
            }

        if self.subnet_id:
            # AWS expect security group *ids* when calling via this technique
            # create network interface with security_groups and public ip address
            interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(
                subnet_id=self.subnet_id,
                groups=self.security_groups,
                associate_public_ip_address=True
                )
            interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(interface)
            kwargs['network_interfaces'] = interfaces
        else:
            # AWS expect security groups *names* when calling via this technique
            kwargs['security_groups'] = self.security_groups

        #kwargs['dry_run'] = True
        reservation = self.conn.run_instances(self.ami, **kwargs)
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
            CNAMEHelper(self.heet, self.get_dnsname(), self)
        if self.get_index_dnsname():
            CNAMEHelper(self.heet, self.get_index_dnsname(), self)
        self.post_converge_hook()
        name = self.get_dnsname() if self.get_dnsname() else self.get_instance().public_dns_name
        self.heet.logger.info("the following instance is ready '%s'" % name)
        return self

    def destroy(self):
        # TODO consider deleting all CNAMEs that point to public dns name
        instance = self.get_instance()
        if not instance:
            return
        self.pre_destroy_hook()
        if self.get_dnsname():
            CNAMEHelper(self.heet, self.get_dnsname(), self).destroy()
        if self.get_index_dnsname():
            CNAMEHelper(self.heet, self.get_index_dnsname(), self).destroy()
        self.heet.logger.info("terminating %s" % instance)
        self.conn.terminate_instances([instance.id])

    def get_cname_target(self):
        """returns public_dns_name"""
        return self.get_instance().public_dns_name

    def get_basename(self):
        """returns a base name, usually a combination of role and environment"""
        str = '%s-%s' % (self.role, self.environment)
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
            return self.get_name() + self.heet.get_value('domain')
        except:
            return None

    def get_index_dnsname(self):
        """returns a unique dns name based on instance get_basename() and index including domain. Return None when no domain provided or other exception"""
        try:
            return "%s-%02d%s" % (self.get_basename(), self.index, self.heet.get_value('domain'))
        except:
            return None

    def set_tag(self, key, value):
        """add tag to the instance. This operation is idempotent. Tags are automatically destroyed when instances are terminated"""
        self.heet.logger.debug("setting tag %s=%s on instance %s" % (key, value, self.get_instance()))
        self.get_instance().add_tag(key, value)


class CNAMEHelper(AWSHelper):
    "modular and convergent route53 records"

    def __init__(self, heet, name, value, **kwargs):
        self.heet = heet
        self.name = name
        self.value = value
        self.zone_id = self.heet.get_value('zone_id')
        self.domain = self.heet.get_value('domain')
        self.ttl = self.heet.get_value('ttl', kwargs, default=300)
        self.conn = boto.connect_route53(
            aws_access_key_id=heet.access_key_id,
            aws_secret_access_key=heet.secret_access_key)
        # get_zone does not like leading periods
        self.zone = self.conn.get_zone(self.domain.lstrip('.'))
        heet.add_resource(self)

    def get_resource_object(self):
        self.record = self.zone.get_cname(self.name)
        return self.record

    def converge(self):
        if self.get_resource_object():
            return self
        # if the target is a subclass of AWSHelper, execute the overloaded method to get the true target
        if isinstance(self.value, AWSHelper):
            self.value = self.value.get_cname_target()
        self.heet.logger.info("creating CNAME record %s to %s for ttl=%s" % (self.name, self.value, self.ttl))
        changes = boto.route53.record.ResourceRecordSets(self.conn, self.zone_id)
        change = changes.add_change("CREATE", self.name, "CNAME", self.ttl)
        change.add_value(self.value)
        result = changes.commit()
        return self

    def destroy(self):
        if not self.get_resource_object():
            return
        self.heet.logger.info("deleting CNAME record %s" % (self.name))
        self.zone.delete_cname(self.name)

class GSLBHelper(AWSHelper):
    """modular and convergent weighted+healthchecked dns records. AFAIK, boto 2.21 does not support creating records with healthchecks, so shell out to aws"""

    def __init__(self, heet, name, target, **kwargs):
        self.heet = heet
        # normalize name to have trailing '.'
        self.name = name.rstrip('.') + '.'
        self.target = target
        self.healthcheck_path = self.heet.get_value('healthcheck_path', kwargs)
        self.healthcheck_port = self.heet.get_value('healthcheck_port', kwargs, default=80)
        self.ttl = self.heet.get_value('ttl', kwargs, default=300)
        self.zone_id = self.heet.get_value('zone_id')
        heet.add_resource(self)

    def get_resource_object(self):
        """return record that matches on self.name==Name and self.target==Value or return None"""
        records = self.get_records_with_name(self.name)
        for record in records:
            if record['Name'] == self.name and record['ResourceRecords'][0]['Value'] == self.target:
                return record
        return None

    def converge(self):
        # if the target is a subclass of InstanceHelper, use the public ip address as the target
        if isinstance(self.target, InstanceHelper):
            self.target = self.target.get_instance().ip_address
        healthcheck_id = self.create_health_check()
        if not self.get_resource_object():
            self.create_record(healthcheck_id)
        return self

    def destroy(self):
        """delete all DNS records with this name - possibly more than one"""
        records = self.get_records_with_name(self.name)
        for record in records:
            if record['Name'] != self.name:
                continue
            # TODO consider deleting multiple records in one batch
            if 'HealthCheckId' in record:
                self.delete_health_check(record['HealthCheckId'])
            change_request = {
                "Comment": "deleting GSLBHelper records",
                "Changes": [ {
                        "Action": "DELETE",
                        "ResourceRecordSet":  record
                        } ]
                }
            self.heet.logger.info("deleting A record %s" % self.name)
            self.change_resource_record_sets(change_request)

    def get_records_with_name(self, name):
        records = []
        cmd = ['aws', 'route53', 'list-resource-record-sets', '--hosted-zone-id', self.zone_id, '--start-record-name', name]
        output = self.heet.exec_awscli(cmd)
        var = json.loads(output)
        for record in var['ResourceRecordSets']:
            if record['Name'] == name:
                records.append(record)
            else:
                return records
        if var['IsTruncated']:
            raise Exception("there are more records for %s than can fit in an untruncated batch" % name)
        return []

    def create_record(self, healthcheck_id):
        change_request = {
            "Comment": "creating DNS A record with a health check",
            "Changes": [
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": {
                        "Name": self.name,
                        "Type": "A",
                        "SetIdentifier": self.target,
                        "Weight": 100,
                        "TTL": self.ttl,
                        "ResourceRecords": [ { "Value": self.target } ],
                        "HealthCheckId": healthcheck_id
                        }
                    }
                ]
            }
        self.heet.logger.info("creating A record %s to %s for ttl=%s using healthcheck %s" % (self.name, self.target, self.ttl, healthcheck_id))
        self.change_resource_record_sets(change_request)

    def change_resource_record_sets(self, change_request):
        """executes change-resource-record-sets command with JSON argument"""
        # it was easier to write json to temp file instead of passing as subprocess arg
        fd, temp_path = tempfile.mkstemp(dir='/tmp')
        file = open(temp_path, 'w')
        file.write(json.dumps(change_request))
        file.close()
        os.close(fd)

        # putting json on command line did not work: '--change-batch', "'" + json.dumps(change_request) + "'"
        cmd = ['aws', 'route53', 'change-resource-record-sets', '--hosted-zone-id', self.zone_id, '--change-batch', 'file://' + temp_path]
        output = self.heet.exec_awscli(cmd)
        os.remove(temp_path)

    def create_health_check(self):
        """creates Route53 health check and returns healthcheck id"""
        # TODO consider passing FullyQualifiedDomainName if http health check needs Host header
        cmd = ['aws', 'route53', 'create-health-check', '--caller-reference', self.target, '--health-check-config', 'IPAddress=%s,Port=%s,Type=%s,ResourcePath=%s' % (self.target, self.healthcheck_port, 'HTTP', self.healthcheck_path)]
        output = self.heet.exec_awscli(cmd)
        var = json.loads(output)
        return var['HealthCheck']['Id']

    def delete_health_check(self, healthcheck_id):
        self.heet.logger.info("deleting healthcheck %s" % healthcheck_id)
        cmd = ['aws', 'route53', 'delete-health-check', '--health-check-id', healthcheck_id]
        try:
            output = subprocess.check_output(cmd)
        except Exception:
            self.heet.logger.debug("healthcheck %s may not have existed" % healthcheck_id)
