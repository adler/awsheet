from .awshelper import AWSHelper
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
import collections
import ipaddress

#- no need for a full class. These are simple tuples
SecurityGroupRule = collections.namedtuple('SecurityGroupRule', ['ip_protocol', 'from_port', 'to_port', 'cidr_ip', 'src_group'])

#- this defines the identity of the security group to Heet Code
#- as long as none of these change, we will converge the same AWS resource
#-     VPC ID
#-     Heet Project Name (Base Name / the name of the script)
#-     Heet Environment (usually, testing, staging or production)
#-     Security Group Name
SgTag = collections.namedtuple('SecurityGroupIDTag',[ 'environment', 'project_name', 'vpc_id', 'sg_name'])



class SecurityGroupHelper(AWSHelper):
    """modular and convergent security groups in VPC (and only in VPC)
    Params"""

    def __init__(self, heet, base_name, description, rules=None):
        self.heet = heet
        self.base_name = base_name
        self.description = description
        self.name = self.build_name()
        self.region = self.heet.get_region()
        self.vpc_id = self.heet.get_value('vpc_id', required=True)

        #- these are actually dependent on the above working
        self.tag = self.build_tag()

        self.conn = boto.ec2.connect_to_region(
            self.region,
            aws_access_key_id=heet.access_key_id,
            aws_secret_access_key=heet.secret_access_key)

        #- when we create a rule that references another group
        #- we have to check that group exists
        #- so, when we do that check, we cache the resulting objects
        #- here. Saves extra calls to the API, which can be throttled.
        self.src_group_references = {}

        self.rules = set()
        #- this will actually make API calls if there is a reference to another group
        if rules is not None:
            for rule in rules:
                self.add_rule(rule)


        #- Post Init Hook
        self.post_init_hook()

        # this will call "this".converge()
        heet.add_resource(self)




    def __str__(self):
        return "SecurityGroup %s" % self.name



    def normalize_aws_sg_rules(self, aws_sg):
        """AWS has grants and rules, but we work with them as a logical unit.
        The rules have the ip_protocol, from_port, to_port while the grants have the remaining parameters,
        which are the mutually exclusive group_id or cidr_ip parameters"""

        normalized_rules = []
        if aws_sg is not None:
            for rule in aws_sg.rules:
                for grant in rule.grants:
                    rule = SecurityGroupRule(rule.ip_protocol, rule.from_port, rule.to_port, grant.cidr_ip, grant.group_id)
                    #- be sure that we are always comparing similarly normalized rules 
                    #- apply self.normalize_rule to API returned rules as well
                    normalized_rules.append(self.normalize_rule(rule))
                
            return normalized_rules



    def get_resource_object(self):
        """Get the Boto Version of this security group from EC2 via API"""
        (tag_name, tag_value) = self.tag
        groups = self.conn.get_all_security_groups(filters={'tag-key' : tag_name, 'tag-value' :tag_value})

        if groups:
            #- if there's more than one security group in the same project and environment with the same name,
            #- this is worthy of logging an error as it isn't expected
            if len(groups) > 1:
                self.heet.logger.warn("multiple security groups returned!: search tag:[{}: {}]".format(tag_name, tag_value))
            return groups[0]

        else:
            return None

    def rule_fails_check(self, rule):
        """Checks that the rule has all the needed attributes
        Returns a list of strings with error messages for each test the rule failed.
        If it passes, the list is empty."""

        #- a list of all the ways that the rule has failed
        rule_status = []

        if rule.ip_protocol not in ['tcp','udp', 'icmp', '-1']:
            rule_status.append('bad value for ip_protocol in rule {}'.format(str(rule)))

        #- try to convert to float to check if it is a valid port number
        try:
            if rule.from_port < 0 and rule.from_port != -1:
                rule_status.append('rule from_port is a negative number that is not -1')
                raise TypeError()

            float(rule.from_port)

        except TypeError as err:
            if rule.from_port is None:
                pass
            else:
                rule_status.append('rule from port is not a valid integer')

        try:
            if rule.to_port < 0 and rule.to_port != -1:
                rule_status.append('rule to_port is a negative number that is not -1')
                raise TypeError()
            float(rule.to_port)

        except TypeError as err:
            if rule.to_port is None:
                pass
            else:
                rule_status.append('rule to port is not a valid integer')

        #- need to have exactly one of src_group, cidr_ip
        if rule.cidr_ip is not None:
            if rule.src_group is not None:
                rule_status.append('Can\'t have both cidr_ip and src_group set simultaneously: rule {}'.format(str(rule)))

            else:
                #- test the cidr_ip
                try:
                    ipaddress.IPv4Network(unicode(rule.cidr_ip))
                except ValueError as err:
                    rule_status.append('rule has an invalid cidr_ip value')

        elif rule.src_group is None:
            rule_status.append('Must specify one or other of [cidr_ip, src_group]')
               
        else:
            #- get the boto object for the reference security group so we
            #- can pass that object into boto's authorize() method
            src_group_resource = self.conn.get_all_security_groups(group_ids=rule.src_group)
            if len(src_group_resource) <= 0:
                rule_status.append('References another security group ID [{}] that doesn\'t exist'.format(rule.src_group))
            else:
                self.heet.logger.debug('added src_group_references[{}]'.format(rule.src_group))
                self.src_group_references[rule.src_group] = src_group_resource[0]

        return rule_status


    def normalize_rule(self, rule):
        """Normalize attributes that can have multiple values representing the same thing into one well-defined value
        Currently only checks from_port and to_port for '-1' or None and normalizes them to be None as that's what the API returns"""
        new_rule = rule
        #- we check for None explicitly also to short-circuit else the int() will fail w/ TypeError and we want it to pass
        if rule.from_port is None or rule.to_port is None or int(rule.from_port) == -1 or int(rule.to_port) == -1:
            new_rule = SecurityGroupRule(ip_protocol=rule.ip_protocol, from_port=None, to_port=None, cidr_ip=rule.cidr_ip, src_group=rule.src_group)
        return new_rule



    def add_rule(self, rule):
        """Print out why a rule fails to be added, else add a rule to this security group"""
        failures = self.rule_fails_check(rule)
        if not failures:
            normalized_rule = self.normalize_rule(rule)
            self.rules.add(normalized_rule)
        else:
            for err in failures:
                self.heet.logger.error('Security Group failed sanity checks: ')
                self.heet.logger.error('    : ' + err)
        return



    def build_tag(self):
        """The tag is what defines a security group as a unique component of heet code
        This format has the following consequences:
            * you can change the id of a security group and still converge
            * you can not converge across projects, environments or sgs with different names, or different VPCs
            * you can change the rules of an SG and converge"""

        sg_tag = SgTag(self.heet.get_environment(), self.heet.base_name, self.vpc_id, self.name)
        tag_value = ':'.join(sg_tag)
        tag_name = 'heet_id'

        return (tag_name, tag_value)



    def build_name(self):
        """The name of the security group is basically the concatenated in order, minus the vpc id
        NB: AWS only determines SG uniqueness by (VPC_ID, SG Name), so if you want the same code for different environments,
        you have to add some additional environment-specific info to the name"""
        return '-'.join([self.heet.get_environment(), self.heet.base_name, self.base_name])



    def converge(self):
        """Adds missing rules, revokes extra rules, creates entire group if necessary"""

        self.heet.logger.info("converging security group: %s" % self.name)

        remote_sg = self.get_resource_object()
        if remote_sg is None:
            self.heet.logger.debug("creating new group: %s" % self.name)
            remote_sg = self.conn.create_security_group(self.name, self.description, self.vpc_id)
            (tag_name,tag_value) = self.tag
            remote_sg.add_tag(key=tag_name, value=tag_value)
            remote_rules = set()

        else:
            self.heet.logger.debug("Using pre-existing group: %s" % self.name)
            remote_rules = set(self.normalize_aws_sg_rules(remote_sg))

        if self.rules:
            desired_rules = set(self.rules)
        else:
            desired_rules = set()

        for rule in desired_rules:
            #- if it isn't there, add it
            if rule in remote_rules:
                self.heet.logger.info("Already Authorized: %s on %s" % (rule, self))
            else:
                self.heet.logger.info("Adding Authorization: %s on %s" % (rule, self))
                #- use the src_group object we already got when we checked the rule
                if rule.src_group:
                    remote_sg.authorize(rule.ip_protocol,rule.from_port, rule.to_port,rule.cidr_ip, self.src_group_references[rule.src_group])
                else:
                    remote_sg.authorize(rule.ip_protocol,rule.from_port, rule.to_port,rule.cidr_ip)


        #- remove all the rules that we didn't explicitly declare we want in this group
        for rule in remote_rules:
            if rule not in desired_rules:
                self.heet.logger.info("Removing remote rule not declared locally: {} in {}".format(rule, self))

                #- boto-specific: get the referring security group object to delete this rule
                ref_sg = None
                if rule.src_group is not None:
                    ref_sg = self.conn.get_all_security_groups(group_ids=rule.src_group)
                    if len(ref_sg) >= 1:
                        ref_sg = ref_sg[0]
                    else:
                        #TODO: create a boto object of needed type to pass to revoke w/out searching API objects first
                        self.heet.logger.error("Rule to delete references another Security Group that no longer exists. Will fail...")
                        pass

                remote_sg.revoke(rule.ip_protocol, rule.from_port, rule.to_port, rule.cidr_ip, ref_sg)

        #- Post Converge Hook
        self.post_converge_hook()



    def destroy(self):
        if not self.get_resource_object():
            return

        #- Pre Destroy Hook
        self.pre_destoy_hook()
        self.heet.logger.info("deleting SecurityGroup record %s" % (self.name))
        while True:
            try:
                self.conn.delete_security_group(name=self.name)
                return
            except:
                # instances may still be using this group
                self.heet.logger.debug("unable to delete %s just yet. will try again..." % (self.name))
                time.sleep(3)
