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
import boto.exception
import copy

#- used to wait between successive API calls
AWS_API_COOLDOWN_PERIOD = 1.0


#TODO: IMPLEMENT TAGGING

#- no need for a full class. These are simple tuples
#- TODO: actually having rules as immutables makes normalization more complex.
#-       refactor this particular tuple into its own class and define rules of
#-       interaction between security groups and rules they contain
#-       as rules themselves do need access to the heet object and to the boto_sg
#-       to perform some aspects of normalization
SecurityGroupRule = collections.namedtuple('SecurityGroupRule', ['ip_protocol', 'from_port', 'to_port', 'cidr_ip', 'src_group'])

#- rm_group: only try to delete the group, fail if the API call fails
#- rm_instances: delete all the instances in this group before attempting deletion of this security group
#- rm_enis: delete all of the Elastic Network Interfaces in this security group before attempting deletion of this security group 
SecurityGroupDeleteMode = collections.namedtuple('SecurityGroupDeleteMode', ['rm_group', 'rm_instances', 'rm_enis'])


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

    def __init__(self, heet, base_name, description, rules=None, vpc_id=None, rm_group=True, rm_instances=False, rm_enis=False):
        self.heet = heet
        self.base_name = base_name
        self.description = description
        self.aws_name = self.build_aws_name(self.base_name)
        self.region = self.heet.get_region()
        self.vpc_id = self.heet.get_value('vpc_id', required=True)
        self._resource_object = None
        self.delete_modes = SecurityGroupDeleteMode(rm_group, rm_instances, rm_enis)
        self.aws_id = None

        #- helps to know how many we have done, how many left
        self._num_converged_dependencies = 0

        self.heet.logger.debug('^^^ SGH init: [{}]'.format(self.base_name))
        #- these are actually dependent on the above working
        self.heet_id_tag = self.build_heet_id_tag()

        self.conn = boto.ec2.connect_to_region(
            self.region,
            aws_access_key_id=heet.access_key_id,
            aws_secret_access_key=heet.secret_access_key)

        #- when we create a rule that references another group
        #- we have to check that group exists
        #- so, when we do that check, we cache the resulting objects
        #- here. Saves extra calls to the API, which can be throttled.
        self.src_group_references = dict()

        self.rules = set()

        #- this is where we put the rules that refer to other AWSHeet SGs that are also declared
        #- in this same module. Dict Key for each is the rule's src_group attribute
        self.dependent_rules = dict()

        #- this will actually make API calls
        #- to get the source group reference objects
        if rules is not None:
            for rule in rules:
                self.add_rule(rule)


        #- Post Init Hook
        self.post_init_hook()

        #- add ourselves to the heet dict so we are reachable by an '@' reference
        heet.add_resource_ref(self, self.base_name_to_ref(self.base_name))

        # this will callback the new instance's securitygrouphelper.converge()
        heet.add_resource(self)




    def __str__(self):
        return "SecurityGroup %s" % self.aws_name



    def normalize_aws_sg_rules(self, aws_sg):
        """AWS has grants and rules, but we work with them as a logical unit.
        The rules have the ip_protocol, from_port, to_port while the grants have the remaining parameters,
        which are the mutually exclusive group_id or cidr_ip parameters
        Also normalize sg-ids that are references to 'self'
        and convert the security group IDs to resource references for SGs in this module"""

        boto_self = self.get_resource_object()
        normalized_rules = set()
        if aws_sg is not None:
            for rule in aws_sg.rules:
                for grant in rule.grants:
                    normalized_group_id = grant.group_id
                    rule = SecurityGroupRule(rule.ip_protocol, rule.from_port, rule.to_port, grant.cidr_ip, normalized_group_id)

                    #- be sure that we are always comparing similarly normalized rules 
                    #- apply self.normalize_rule to API returned rules as well
                    normalized_rules.add(self.normalize_rule(rule))
                
            return normalized_rules



    def get_resource_object(self):
        """Get or create the Boto Version of this security group from EC2 via API"""

        boto_group = None
        #- build the tag and find it by tag
        (tag_name, tag_value) = self.heet_id_tag
        matching_groups = self.conn.get_all_security_groups(filters={'tag-key' : tag_name, 'tag-value' :tag_value})

        if matching_groups:
            #- if there's more than one security group in the same project and environment with the same name,
            #- this is worthy of logging an error as it isn't expected
            if len(matching_groups) > 1:
                self.heet.logger.warn("multiple security groups returned!: search tag:[{}: {}]".format(tag_name, tag_value))
            boto_group = matching_groups[0]
            self.aws_id = boto_group.id

        return boto_group



    def get_or_create_resource_object(self):
        """Get or create the Boto Version of this security group from EC2 via API"""

        (tag_name, tag_value) = self.heet_id_tag
        boto_group = self.get_resource_object()
        if not boto_group and not self.heet.args.destroy:
            #- it doesn't exist yet
            try:
                self.heet.logger.debug('get_or_create_resource_object: creating new security group')
                boto_group = self.conn.create_security_group(name=self.aws_name, description=self.description, vpc_id=self.vpc_id)
            except boto.exception.EC2ResponseError as err:
                print 'AWS EC2 API error: {} ({})'.format(err.message, err)
                return None

            self.heet.logger.debug('get_or_create_resource_object: successfully created new security group, waiting to tag')
            time.sleep(AWS_API_COOLDOWN_PERIOD)
            self.heet.logger.debug('get_or_create_resource_object: tagging new security group: [{}:{}]'.format(tag_name, tag_value))
            try:
                #- sometimes a short sleep isn't enough, and we really don't want to exit before tagging
                #- as that makes the next convergence cycle fail until the group is deleted manually.
                boto_group.add_tag(key=tag_name, value=tag_value)
                self.heet.logger.debug('get_or_create_resource_object: successfully created new tagged group.')
                self.aws_id = boto_group.id
            except boto.exception.EC2ResponseError as err:
                if err.code == 'InvalidGroup.NotFound':
                    self.heet.logger.debug('get_or_create_resource: setting ID tag failed. Waiting to try again...')
                    time.sleep(3)
                    boto_self.add_tag(key=tag_name, value=tag_value)
                else:
                    raise err

        return boto_group




    def make_key_from_rule(self, rule):
        """Just join all the things together to make a unique string"""
        key = '/'.join([str(rule.ip_protocol), str(rule.from_port), str(rule.to_port), str(rule.cidr_ip), str(rule.src_group)])
        return key



    def get_src_group_from_key(self, key):
        """Just undo make_key_from_rule to get the source group"""
        return key.split('/')[-1]



    def rule_fails_check(self, rule):
        """Checks that the rule has all the needed attributes
        Returns a list of strings with error messages for each test the rule failed.
        If it passes, then the list will be empty.
        As well, this populates self.src_group_references dict"""

        #- a list of all the ways that the rule has failed
        rule_status = []

        if str(rule.ip_protocol) not in ['tcp','udp', 'icmp', '-1']:
            rule_status.append('bad value for ip_protocol in rule {}'.format(str(rule)))

        #- try to convert to float to check if it is a valid port number
        try:
            if rule.from_port is not None and rule.from_port < 0 and rule.from_port != -1:
                rule_status.append('rule from_port is a negative number that is not -1: [{}]'.format(rule.from_port))
                raise TypeError()
            float(rule.from_port)

        except TypeError as err:
            if rule.from_port is None:
                pass
            else:
                rule_status.append('rule from port is not a valid integer')

        try:
            if rule.to_port is not None and rule.to_port < 0 and rule.to_port != -1:
                rule_status.append('rule to_port is a negative number that is not -1: [{}]'.format(rule.to_port))
                raise TypeError()
            float(rule.to_port)

        except TypeError as err:
            if rule.to_port is None:
                pass
            else:
                rule_status.append('rule to port is not a valid integer')

        #- Check the (.cidr_ip, .src_group) pair compliance
        #- need to have exactly one of src_group, cidr_ip
        if rule.cidr_ip is not None:
            #self.heet.logger.debug(' ^^^ rule has cidr_ip')
            if rule.src_group is not None:
                self.heet.logger.debug(' ^^^ rule has both cidr_ip and src_group')
                rule_status.append('Can\'t have both cidr_ip and src_group set simultaneously: rule {}'.format(str(rule)))

            else:
                #self.heet.logger.debug(' ^^^ rule has only cidr_ip')
                #- test the cidr_ip
                try:
                    ipaddress.IPv4Network(unicode(rule.cidr_ip))
                except ValueError as err:
                    #self.heet.logger.debug(' ^^^ rule has invalid cidr_ip')
                    rule_status.append('rule has an invalid cidr_ip value')

        elif rule.cidr_ip is None and rule.src_group is None:
            #self.heet.logger.debug(' ^^^ rule has neither cidr_ip nor src_group')
            rule_status.append('Must specify one or other of [cidr_ip, src_group]')
               
        else:
            if rule.src_group == 'self':
                #self.heet.logger.debug(' ^^^ rule src_group refers to "self"')
                boto_self = self.get_or_create_resource_object()
                if not boto_self:
                    return
                self.src_group_references[boto_self.id] = boto_self
            elif rule.src_group != 'self' and not self.rule_has_dependent_reference(rule):
                #self.heet.logger.debug('^^^ rule that references AWS SG directly: {}'.format(rule.src_group))
                #- get the boto object for the reference security group so we
                #- can pass that object into boto's authorize() method
                src_group_resource = self.conn.get_all_security_groups(group_ids=rule.src_group)
                if len(src_group_resource) <= 0:
                    #self.heet.logger.debug('^^^ rule references another security group ID [{}] that doesn\'t exist'.format(rule.src_group))
                    rule_status.append('References another security group ID [{}] that doesn\'t exist'.format(rule.src_group))
                else:
                    self.src_group_references[rule.src_group] = src_group_resource[0]
                    self.heet.logger.debug('added src_group_references[{}]'.format(rule.src_group))
            elif self.heet.is_resource_ref(rule.src_group):
                #- this is a reference to another heet security group helper object
                #- we should make sure that this actually exists before saying its okay
                #- but we can only do that after we have a comprehensive list of all the
                #- security groups to be created, which we will only have at the end of the
                #- program.
                #- So here, we add this name to a list of things which will be done at exit.
                #self.heet.logger.debug('^^^ rule seems to be a new style resource reference.')
                key = self.make_key_from_rule(rule)
                if key not in self.dependent_rules:
                    self.dependent_rules[key] = rule
                    self.heet.add_dependent_resource(self, key)

        return rule_status



    def is_aws_reference(self, src_group):
        """Check if the src_group argument looks like an AWS security group ID
        Just means the first three characters are 'sg-'"""

        is_ref = False
        if src_group and src_group[0] == 's' and src_group[1] == 'g' and src_group[2] == '-' and len(src_group.split('-')) == 2:
            is_ref = True

        return is_ref


    def get_boto_src_group(self, src_group):
        """src_group can be:
        * @resource-reference
        * 'sg-xxxxxxx'

        Return a boto object that can be used in authorize / revoke"""
        boto_sg = None
        if self.heet.is_resource_ref(src_group):
            self.heet.logger.debug('get_boto_src_group: will try to look [{}] up as heet resource ref'.format(src_group))
            try:
                rr = self.heet.resource_refs[src_group]
                boto_sg = rr.get_resource_object()
            except KeyError as err:
                self.heet.logger.debug('get_boto_src_group: failed to lookup [{}] in heet resource refs table'.format(src_group))
                boto_sg = None
        elif self.is_aws_reference(src_group):
            self.heet.logger.debug('get_boto_src_group: will try to retrieve sg id [{}] from AWS API'.format(src_group))
            #XXX we should actually get it by tag
            # move create tag to be a utility function
            #(tag_name, tag_value) = self.heet_id_tag
            #matching_groups = self.conn.get_all_security_groups(filters={'tag-key' : tag_name, 'tag-value' :tag_value})
            matching_groups = self.conn.get_all_security_groups(group_ids=[src_group])
            if not matching_groups:
                self.heet.logger.debug('get_boto_src_group: aws returned no groups with tag ([{}],[{}])'.format(tag_name, tag_value))
                boto_sg = None
            else:
                self.heet.logger.debug('get_boto_src_group: aws returned matching group')
                boto_sg = matching_groups[0]
        else:
            self.heet.logger.debug('get_boto_src_group: can not tell what type of src_group format this is: [{}]'.format(src_group))
            boto_sg = None

        return boto_sg



    def normalize_rule(self, rule):
        """Normalize SecurityGroupRule attributes that can have multiple values representing the same thing into one well-defined value
        Currently only checks from_port and to_port for '-1' or None and normalizes them to be None as that's what the API returns"""

        #- make a mutable copy
        new_rule = {'ip_protocol' : rule.ip_protocol, 
                'from_port' : rule.from_port,
                'to_port' : rule.to_port,
                'cidr_ip' : rule.cidr_ip,
                'src_group' : rule.src_group }

        #- just go through and normalize all the values one by one and make a new rule at the end
        #- out of all the stuff we collect throughout the normalization tests
        if new_rule['src_group'] == 'self':
            #- normalize_rule called from add_rules which is called from init, so we may not exist: call get_or_create.
            boto_self = self.get_or_create_resource_object()
            if not boto_self:
                return rule

            new_rule['src_group'] = boto_self.id

        if self.heet.is_resource_ref(new_rule['src_group']):
            try:
                #- try to look it up
                self.heet.logger.debug('Normalizing resource_reference: {}'.format(rule.src_group))
                #boto_sg = self.heet.resource_refs[new_rule['src_group']].get_resource_object()
                boto_sg = self.get_boto_src_group(rule.src_group)
                if boto_sg:
                    self.heet.logger.debug('*** resolved resource_reference: {}'.format(rule.src_group))
                    self.heet.logger.debug('*** adding local resource_reference: {}'.format(rule.src_group))
                    self.src_group_references[boto_sg.id] = boto_sg
                    new_rule['src_group'] = boto_sg.id
                else:
                    self.heet.logger.debug('normalize_rule: get_resource_object returned nothing for group: {}.'.format(rule.src_group))

            except KeyError as err:
                self.heet.logger.debug('*** normalize_rule: resource_reference not found: {}, will handle in 2nd pass'.format(rule.src_group))
                #- it wasn't in the reference table yet, 
                #- we'll handle this in converge() and converge_dependency() 
                pass

        if rule.ip_protocol == -1:
            self.heet.logger.debug('Normalizing ip_protocol: {} to str(-1)'.format(rule.ip_protocol))
            new_rule['ip_protocol'] = '-1'

        #- we check for None explicitly also to short-circuit else the int() will fail w/ TypeError and we want it to pass
        if new_rule['from_port'] is None or new_rule['to_port'] is None or int(new_rule['from_port']) == -1 or int(new_rule['to_port']) == -1:
            #self.heet.logger.debug('Normalizing port range: {} .. {} to [None .. None]'.format(rule.from_port, rule.to_port))
            new_rule['from_port'] = None
            new_rule['to_port'] = None

        
        final_rule = SecurityGroupRule(new_rule['ip_protocol'], new_rule['from_port'], new_rule['to_port'], new_rule['cidr_ip'], new_rule['src_group'])
        return final_rule



    def add_rule(self, rule):
        """Print out why a rule fails to be added, else add a rule to this security group
        Rule will be normalized and added to one of two lists of rules:
            One group is for rules that can be converged immediately
            (those ones have no src_group resource references)
            The other group is for rules that will be converged after the resource
            reference table has been built
        """
        normalized_rule = self.normalize_rule(rule)
        failures = self.rule_fails_check(normalized_rule)
        if not failures:
            self.rules.add(normalized_rule)
        else:
            for err in failures:
                self.heet.logger.error('Security Group failed sanity checks: ')
                self.heet.logger.error('    : ' + err)
        return



    def build_heet_id_tag(self):
        """The tag is what defines a security group as a unique component of heet code
        This format has the following consequences:
            * you can change the id of a security group and still converge
            * you can not converge across projects, environments or sgs with different names, or different VPCs
            * you can change the rules of an SG and converge"""

        sg_tag = SgTag(self.heet.get_environment(), self.heet.base_name, self.vpc_id, self.aws_name)
        tag_value = ':'.join(sg_tag)
        tag_name = 'heet_id'

        return (tag_name, tag_value)



    def build_aws_name(self, base_name):
        """The name of the security group is basically the Tag concatenated in order, minus the vpc id
        NB: AWS only determines SG uniqueness by (VPC_ID, SG Name), so if you want the same code for different environments,
        you have to add some additional environment-specific info to the name"""
        return '-'.join([self.heet.get_environment(), self.heet.base_name, base_name])



    def rule_has_dependent_reference(self, rule):
        """Check if the rule refers to a security group that is another Heet object
        For now, we do that by passing in the heet base_name of the group prefixed with an '@'"""
        return self.heet.is_resource_ref(rule.src_group)



    def base_name_to_ref(self, base_name):
        """Converts the Heet Script's SG base name into a name reference.
        Currently, this just means that it is prepended with an '@'"""
        return '@' + base_name



    def ref_to_base_name(self,base_name):
        """The opposite of the above."""
        if base_name[0] == '@':
            return base_name[1:]
        else:
            self.heet.logger.error("Trying to dereference a SG name that isn't a reference: {}".format(base_name))
            return None



    def converge(self):
        """Adds missing rules, revokes extra rules, creates entire group if necessary
        if the rule can't be converged yet (due to an unresolveable resource reference, 
        we'll let heet know to call us at the module exit time and re-try via converge_dependency()
        when we have the full module resource reference table"""

        self.heet.logger.info("Converging security group: %s" % self.aws_name)

        boto_self = self.get_resource_object()
        if boto_self is None:
            self.heet.logger.debug("Creating new group: %s" % self.aws_name)
            boto_self = self.conn.create_security_group(self.aws_name, self.description, self.vpc_id)
            remote_rules = set()
            (tag_name,tag_value) = self.heet_id_tag
            try:
                boto_self.add_tag(key=tag_name, value=tag_value)
            except boto.exception.EC2ResponseError as err:
                if err.code == 'InvalidGroup.NotFound':
                    #- wait for API consistency - sleep momentarily before adding tag
                    self.heet.logger.debug('converge: set_tag failed due to SG not found. Waiting a moment then trying again.')
                    time.sleep(3)
                    boto_self.add_tag(key=tag_name, value=tag_value)
        else:
            self.heet.logger.debug("Using pre-existing group: %s" % self.aws_name)
            remote_rules = set(self.normalize_aws_sg_rules(boto_self))

        self.src_group_references['self'] = boto_self
        self.src_group_references[boto_self.id] = boto_self

        if self.rules:
            desired_rules = set(self.rules)
        else:
            desired_rules = set()

        for rule in desired_rules:
            #- if it isn't there, add it
            if rule in remote_rules:
                self.heet.logger.info("Already Authorized: %s on %s" % (rule, self))
            else:
                if rule.src_group:
                    #- check if this rule can be converged now or later
                    if self.rule_has_dependent_reference(rule):
                        self.heet.logger.debug("-- Rule refers to another Heet group. Will converge_dependency() atexit: {}".format(rule))
                        key = self.make_key_from_rule(rule)
                        if key not in self.dependent_rules:
                            self.dependent_rules[key] = rule
                            self.heet.add_dependent_resource(self, key)
                    elif self.is_aws_reference(rule.src_group):
                        #- use the src_group object we already got when we checked the rule
                        self.heet.logger.info("Adding Authorization: %s on %s" % (rule, self))
                        try:
                            boto_self.authorize(rule.ip_protocol,rule.from_port, rule.to_port,rule.cidr_ip, self.src_group_references[rule.src_group])
                        except KeyError as err:
                            print ""
                            print ""
                            print 'FATAL ERROR: key error in src_group_references. looked for [{}] in:'.format(rule.src_group)
                            print self.src_group_references
                            print ""
                            print ""
                            os._exit(-1)

                    else:
                        print "Unexpected Rule format: {}".format(rule)
                        raise AttributeError('Source Group reference can NOT be converged')
                else:
                    boto_self.authorize(rule.ip_protocol,rule.from_port, rule.to_port,rule.cidr_ip)

        #- remove all the rules that we didn't explicitly declare we want in this group
        #- if they can currently be resolved (can only resolve names present in the resource reference table at the moment
        #- of execution. )
        #- any desired rule that is still in resource reference form because it couldn't be resolved yet will not match
        #- anything, so we remove all the resource reference rules from the desired rules before comparison
        desired_rules_copy = copy.copy(desired_rules)
        for rule in desired_rules_copy:
            if self.rule_has_dependent_reference(rule):
                desired_rules.discard(rule)

        for rule in remote_rules:
            if rule not in desired_rules:
                if self.is_aws_reference(rule.src_group):
                    #- skip this rule for now
                    self.heet.logger.debug('converge: skipping rule with aws sg id: [{}]'.format(rule))
                    key = self.make_key_from_rule(rule)
                    if key not in self.dependent_rules:
                        self.dependent_rules[key] = rule
                        self.heet.add_dependent_resource(self, key)
                    #- continue looping, but skip this rule now that we've registered it for convergence at exit
                    continue
                else:
                    self.heet.logger.info("Removing remote rule not declared locally: {} in {}".format(rule, self))
                    print ""
                    print ""
                    print "DEBUG: removing rule"
                    print "remote: "
                    print str(remote_rules)
                    print ""
                    print "current rule being tested: "
                    print str(rule)
                    print ""
                    print "desired rules: "
                    print str(desired_rules)
                    print ""
                    print ""
    
                    #- boto-specific: get the referring security group boto-level object to delete this rule
                    #- TODO: this may be redundant if normalization strips the boto object for the src_group
                    #- as I'm resolving here. This isn't necessary if the pre-normalized rule has the object in it
                    ref_sg = None
                    if rule.src_group is not None:
                        if rule.src_group == 'self':
                            ref_sg = [self.get_or_create_resource_object()]
                        elif self.is_aws_reference(rule.src_group):
                            ref_sg = self.conn.get_all_security_groups(group_ids=rule.src_group)
                            if len(ref_sg) >= 1:
                                ref_sg = ref_sg[0]
                            else:
                                self.heet.logger.error("Rule to delete references another Security Group that no longer exists. Will fail...")
                                reg_sg = None

                    if rule.src_group is not None and ref_sg is None:
                        #- if we didn't just find it, skip it for now
                        key = self.make_key_from_rule(rule)
                        if key not in self.dependent_rules:
                            self.dependent_rules[key] = rule
                            self.heet.add_dependent_resource(self, key)
                    else:
                        boto_self.revoke(rule.ip_protocol, rule.from_port, rule.to_port, rule.cidr_ip, ref_sg)

        #- Post Converge Hook
        self.post_converge_hook()



    def converge_dependent_add_rule(self, init_rule):
        """Called from converge_dependency for the rules that needed to be added
        but used a resource reference that couldn't yet be resolved on first pass in converge()"""
        boto_self = self.get_resource_object()
        resource_name = init_rule.src_group
        boto_src_group = self.heet.resource_refs[resource_name].get_resource_object()

        #- TODO: clean this up
        #- we need the ID for comparisons, but we need the object for the API call
        #- and we start with a resource reference
        new_rule = SecurityGroupRule(init_rule.ip_protocol, 
                                     init_rule.from_port, 
                                     init_rule.to_port, 
                                     init_rule.cidr_ip, 
                                     boto_src_group.id)

        normalized_rule = self.normalize_rule(new_rule)

        final_rule = SecurityGroupRule(normalized_rule.ip_protocol, 
                                       normalized_rule.from_port, 
                                       normalized_rule.to_port, 
                                       normalized_rule.cidr_ip, 
                                       boto_src_group)

        remote_rules = self.normalize_aws_sg_rules(boto_self)

        #print "                     ----------------------------------- "
        #print "                    |                                   |"
        #print "                    |              debug_start          |"
        #print "                    |                                   |"
        #print "                     ----------------------------------- "
        #print "________________________________________________________________________________"
        #print "REMOTE RULES:"
        #for rule in remote_rules:
        #    print rule
        #print "________________________________________________________________________________"
        if normalized_rule not in remote_rules:
        #    print "CURRENT RULE:"
        #    print normalized_rule
        #    print "    Not found in: "
        #    print " _______________________________________________________________________________"
        #    print "|_______________________________________________________________________________|"
            boto_self.authorize(final_rule.ip_protocol, final_rule.from_port, final_rule.to_port, final_rule.cidr_ip, final_rule.src_group)
            time.sleep(AWS_API_COOLDOWN_PERIOD)
        return



    def converge_dependent_remove_test(self, remote_rule):
        """Take this rule that has an AWS SG ID and is an existing remote rule and now check if this rule is a desired rule or not."""
        #- first take all the current desired rules and re-normalize them so the resource references will be looked up
        boto_self = self.get_resource_object()
        desired_rules = set()
        for rule_x in self.rules:
            desired_rules.add(self.normalize_rule(rule_x))

        if remote_rule not in desired_rules:
            self.heet.logger.debug('converge_dependent_remove_test: removing rule [{}]'.format(remote_rule))
            boto_src_group = self.get_boto_src_group(remote_rule.src_group)
            boto_self.revoke(remote_rule.ip_protocol, remote_rule.from_port, remote_rule.to_port, remote_rule.cidr_ip, boto_src_group)
        return



    def converge_dependency(self, key):
        """converge_at_exit: this convergence pattern is different than the single-call of converge.
        converge_dependency will be called once for every rule that needed to be converged at exit.

        This is where we converge the rules that refer to other security groups that are declared in the same AWSHeet module
        Dependencies here is any security group rule that referenced another Heet group that is being declared in this script.
        If it is the first time the group is created, the referenced group will not exist yet, and so the rule will fail convergence.
        So, to keep it simple, any group that refers to another group in a Heet script will be put off to be converged after we are 
        sure that the creation of the rule should not fail unless there has been an actual error."""
        print ""
        print "----CONVERGE_DEPENDENCY() {}: {}---- {} of {} rules to process".format(self.base_name, key, self._num_converged_dependencies+1, len(self.dependent_rules))
        #print ""
        self._num_converged_dependencies += 1

        boto_self = self.get_resource_object()
        if not boto_self:
            self.heet.logger.debug('converge_dependency: no boto_object found. returning without issuing any API calls')
            return

        #- lookup the rule as it was when we saved it
        init_rule = self.dependent_rules[key]

        #- grab the group we need from the resource references
        #resource_name = name.split('/')[-1]
        if key == 'DESTROY_AGAIN':
            self.heet.logger.debug('converge_dependency: destroying 2nd round')
            self.destroy()
        else:
            src_group_name = self.get_src_group_from_key(key)
            if self.heet.is_resource_ref(src_group_name):
                #- a bit opaque, but resource references are only called for rules that are trying
                #- to be added, so we know if we see a resource reference here that this rule was 
                #- trying to be added and failed due to a resource reference being unable to be resolved
                self.heet.logger.debug('converge_dependency: add_rule detected: [{}]'.format(init_rule))
                self.converge_dependent_add_rule(init_rule)
            elif self.is_aws_reference(src_group_name):
                #- equally opaque, the only other rules we register to be called back for are rules
                #- that existed remotely that referred to an AWS ID that we couldn't look up at the time
                #- that we needed to check if it should be removed or not
                self.heet.logger.debug('converge_dependency: remove_test detected: [{}]'.format(init_rule))
                self.converge_dependent_remove_test(init_rule)
        return



    def destroy(self):
        """Try to remove everything from existence."""
        boto_self = self.get_resource_object()
        if not boto_self:
            self.heet.logger.debug("destroy [{}]: no resource object found, returning without any API calls.".format(self.base_name))
            return

        #- Pre Destroy Hook
        self.pre_destroy_hook()

        self.heet.logger.info("deleting SecurityGroup [{}]".format(self.aws_name))
        #- first delete any src_group rules so the group can be deleted
        self.heet.logger.debug('destroy [{}]: testing [{}] rules to remove ones w/ src_groups'.format(self.aws_name, len(boto_self.rules)))
        rules_copy = copy.deepcopy(boto_self.rules)
        for boto_rule in rules_copy:
            self.heet.logger.debug('destroy [{}]: testing rule for src_group: [{}]'.format(self.aws_name, boto_rule))
            for boto_grant in boto_rule.grants:
                if boto_grant.group_id is not None:
                    self.heet.logger.debug('destroy [{}]: found rule with group_id: [{}]'.format(self.aws_name, boto_grant.group_id))
                    try:
                        src_group_ref = self.conn.get_all_security_groups(group_ids=[boto_grant.group_id])[0]
                        self.heet.logger.debug('destroy [{}]: removing rule with src_group to remove group.({}:{})'.format(self.aws_name, boto_grant.group_id, src_group_ref.name))
                        boto_self.revoke(boto_rule.ip_protocol, boto_rule.from_port, boto_rule.to_port, boto_grant.cidr_ip, src_group_ref)
                        time.sleep(AWS_API_COOLDOWN_PERIOD)
                    except boto.exception.EC2ResponseError as err:
                        self.heet.logger.debug('destroy [{}]: failed to remove rule: [{}]'.format(self.aws_name, err.message))

        self.heet.logger.debug('destroy [{}]: done removing rules.'.format(self.aws_name))
        try:
            time.sleep(AWS_API_COOLDOWN_PERIOD)
            boto_self.delete()
            self.heet.logger.info('Successfully deleted group {}.'.format(self.aws_name))
        except boto.exception.EC2ResponseError as err:
            if 'DESTROY_AGAIN' in self.dependent_rules:
                self.heet.logger.info("*** Unable to delete {}. {}".format(self.aws_name, err.message))
            else:
                #- try again after all the other groups rules are deleted
                self.heet.add_dependent_resource(self, 'DESTROY_AGAIN')
                self.dependent_rules['DESTROY_AGAIN'] = 'placeholder'

        return
