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

class CloudFormationHelper(AWSHelper):
    "modular and convergent AWS CloudFormation"

    DOES_NOT_EXIST = 'DOES NOT EXIST'

    def __init__(self, heet, **kwargs):
        self.heet = heet
        self.stack_base_name = heet.get_value('stack_base_name', kwargs, required=True)
        self.environment = heet.get_value('environment', kwargs, default=heet.get_environment())
        self.template_file_name = heet.get_value('template_file_name', kwargs)
        self.template = open(self.template_file_name, 'r').read();
        self.version = heet.get_value('version', kwargs, default=heet.get_version())
        self.parameters = heet.get_value('parameters', kwargs, default=())
        if type(self.parameters) is dict:
            self.parameters = tuple(self.parameters.items())
        self.conn = boto.cloudformation.connect_to_region(
            self.heet.get_region(),
            aws_access_key_id=heet.access_key_id,
            aws_secret_access_key=heet.secret_access_key)
        heet.add_resource(self)

    def __str__(self):
        return "CloudFormation %s" % self.stack_name()

    def stack_name(self):
        if self.version:
            return self.environment + '-' + self.stack_base_name + '-v' + self.version
        else:
            return self.environment + '-' + self.stack_base_name

    def describe(self):
        try:
            return self.conn.describe_stacks(self.stack_name())[0]
        except boto.exception.BotoServerError:
            return None

    def status(self):
        stack = self.describe()
        if stack is None:
            return CloudFormationHelper.DOES_NOT_EXIST
        else:
            return stack.stack_status

    def get_output(self, key, default=None):
        stack = self.describe()
        if stack is None:
            return default
        for output in stack.outputs:
            if output.key == key:
                return output.value
        return default

    def get_resource(self, logical_id):
        try:
            resources = self.conn.list_stack_resources(self.stack_name())
        except:
            return None
        for r in resources:
            if r.logical_resource_id == logical_id:
                return r.physical_resource_id
        return None

    def create(self):
        self.heet.logger.info("creating CloudFormation stack '%s'" % self.stack_name())
        self.conn.create_stack(
            self.stack_name(),
            template_body=self.template,
            parameters=self.parameters,
            capabilities=['CAPABILITY_IAM'])

    def update(self):
        try:
            self.heet.logger.info("updating CloudFormation stack '%s'" % self.stack_name())
            self.conn.update_stack(self.stack_name(), template_body=self.template, parameters=self.parameters)
        except boto.exception.BotoServerError as e:
            #self.heet.logger.debug("unable to update - maybe no change of '%s'" % self.stack_name())
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
            if status == 'ROLLBACK_COMPLETE':
                raise Exception("CloudFormation stack '%s' status: %s" % (self.stack_name(), status))
            if re.search('COMPLETE|FAILED', status):
                break
            if status == CloudFormationHelper.DOES_NOT_EXIST:
                break
            self.heet.logger.debug("CloudFormation stack '%s' status: %s" % (self.stack_name(), status))
            time.sleep(5)

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

