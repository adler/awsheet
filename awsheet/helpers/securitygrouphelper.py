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

#- no need for a full class. These are simple tuples
SecurityGroupRule = collections.namedtuple('SecurityGroupRule', ['ip_protocol', 'from_port', 'to_port', 'cidr_ip', 'src_group_name'])

#- this defines the identity of the security group to Heet Code
#- as long as none of these change, we will converge the same AWS resource
#-     VPC ID
#-     Heet Project Name (Base Name / the name of the script)
#-     Heet Environment (usually, testing, staging or production)
#-     Security Group Name
SgTag = collections.namedtuple('SecurityGroupIDTag',[ 'vpc_id', 'project_name', 'environment', 'sg_name'])



class SecurityGroupHelper(AWSHelper):
    """modular and convergent security groups
    Params"""

    def __init__(self, heet, name, description, rules):
        self.heet = heet
        self.name = name
        self.description = description
        self.rules = set(rules)
        self.region = heet.get_region()
        self.tag = self.build_tag()

        self.conn = boto.ec2.connect_to_region(
            self.region,
            aws_access_key_id=heet.access_key_id,
            aws_secret_access_key=heet.secret_access_key)

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
                    normalized_rules.append(SecurityGroupRule(rule.ip_protocol, rule.from_port, rule.to_port, grant.cidr_ip, grant.group_id))
                
            return normalize_rules



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

        #- try to convert to float to check if it is a valid number
        try:
            float(rule.from_port)
        except ValueError as err:
            rule_status.append('rule from port is not a valid integer')

        try:
            float(rule.to_port)
        except ValueError as err:
            rule_status.append('rule to port is not a valid integer')

        #- need to have exactly one of src_group_name, cidr_ip
        if rule.cidr_ip is not None:
            if rule.src_group_name is not None:
                rule_status.append('Can\'t have both cidr_ip and src_group_name set simultaneously: rule {}'.format(str(rule)))

            else:
                #- test the cidr_ip
                try:
                    ipaddress.ipnetwork(rule.cidr_ip)
                except ValueError as err:
                    rule_status.append('rule has an invalid cidr_ip value')

        elif rule.src_group_name is None:
            rule_status.append('Must specify one or other of [cidr_ip, src_group_name]')
            #- TODO: add a parameter to verify the named security group exists
               
        return rule_status



    def add_rule(self, rule):
        """Add a rule to this security group"""
        failures = rule_fails_check(rule)
        if not failures:
            self.rules.add(rule)
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

        sg_tag = SgTag(self.heet.vpc_id, self.heet.base_name, self.heet.environment, self.name)
        tag_value = '/'.join(sg_tag)
        tag_name = 'heet_identity'

        return (tag_name, tag_value)



    def converge(self):
        """Adds missing rules, revokes extra rules, creates entire group if necessary"""

        self.heet.logger.info("converging security group: %s" % self.name)

        current_state = self.get_resource_object()
        if current_state is None:
            current_state = self.conn.create_security_group(self.name, self.description)
            current_rules = set()

        else:
            current_rules = set(self.normalize_aws_sg_rules(current_state))

        for rule in self.rules:
            self.heet.logger.info("authorizing %s on %s" % (rule, self))
            group.authorize(rule.ip_protocol,rule.from_port, rule.to_port,rule.cidr_ip)

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
