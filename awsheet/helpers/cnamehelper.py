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

class CNAMEHelper(AWSHelper):
    "modular and convergent route53 records"

    def __init__(self, heet, name, value, normalize_name=True, **kwargs):
        self.heet = heet
        if normalize_name is True:
            self.name = self.normalize_name(name)
        else:
            self.name = name

        self.value = value
        self.zone_id = self.heet.get_value('zone_id', required=True)
        self.domain = self.heet.get_value('domain', required=True)
        self.ttl = self.heet.get_value('ttl', kwargs, default=300)
        self.conn = boto.connect_route53(
            aws_access_key_id=heet.access_key_id,
            aws_secret_access_key=heet.secret_access_key)
        # get_zone does not like leading periods
        self.zone = self.conn.get_zone(self.domain.lstrip('.'))
        heet.add_resource(self)

    def __str__(self):
        return "CNAME %s" % self.name

    def get_resource_object(self):
        self.record = self.zone.get_cname(self.name)
        return self.record

    def normalize_name(self, name):
        """Apply normalization logic to the name we are creating.
        Currently this only replaces underscores with dashes"""
        return name.replace('_','-')

    def converge(self):
        # if the target is a subclass of AWSHelper, execute the overloaded method to get the true target
        if isinstance(self.value, AWSHelper):
            self.value = self.value.get_cname_target()
        current_record = self.get_resource_object()
        if current_record and current_record.resource_records:
            current_value = current_record.resource_records[0]
            # if CNAME already exists AND points at correct value, do nothing
            if current_value == self.value:
                return self
            # if CNAME already exists AND points at wrong value, delete it before creating new record
            self.heet.logger.info("deleting old CNAME record %s to %s" % (self.name, current_value))
            self.zone.delete_cname(self.name)
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

