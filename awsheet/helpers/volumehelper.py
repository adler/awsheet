from .. awsheet import AWSHeet
from . awshelper import AWSHelper
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

class VolumeHelper(AWSHelper):
    "modular and convergent EBS volumes. support for standard and io1 types (provisioned iops)"

    def __init__(self, heet, size, instance, name, device, zone=None, snapshot=None, volume_type=None, iops=None, dry_run=False):
        self.heet = heet
        self.size = size
        self.instance = instance
        self.name = name
        self.device = device
        self.zone = zone
        self.snapshot = snapshot
        self.volume_type = volume_type
        self.iops = iops
        self.dry_run = dry_run
        self.conn = boto.ec2.connect_to_region(
            heet.get_region(),
            aws_access_key_id=heet.access_key_id,
            aws_secret_access_key=heet.secret_access_key)
        heet.add_resource(self)

    def __str__(self):
        return "Volume %s" % self.name

    def get_resource_object(self):
        for volume in self.conn.get_all_volumes(filters={'tag:'+AWSHeet.TAG:self.name}):
            return volume
        return None

    def wait_until_available(self):
        while True:
            volume = self.get_resource_object()
            if volume.status == 'available':
                return
            self.heet.logger.info("waiting for %s to be available" % self)
            time.sleep(3)

    def converge(self):
        volume = self.get_resource_object()
        instance = self.instance.get_instance()
        if not volume:
            self.heet.logger.info("creating %s" % self)
            if self.zone is None:
                # get zone from instance
                self.zone = instance.placement
            volume = self.conn.create_volume(
                self.size, self.zone, snapshot=self.snapshot, volume_type=self.volume_type,
                iops=self.iops, dry_run=self.dry_run
            )
            self.conn.create_tags(volume.id, {AWSHeet.TAG:self.name})
            self.wait_until_available()
        # TODO verify attached to correct host
        if not volume.status == 'in-use':
            self.heet.logger.info("attaching volume %s to instance %s and device %s" % (volume.id, instance.id, self.device))
            self.conn.attach_volume(volume.id, instance.id, self.device)

    def destroy(self):
        volume = self.get_resource_object()
        if not volume:
            return
        if volume.status == 'in-use':
            self.heet.logger.info("deattaching volume %s" % volume.id)
            self.conn.detach_volume(volume.id)
        self.wait_until_available()
        self.heet.logger.info("deleting Volume %s %s" % (self.name, volume.id))
        self.conn.delete_volume(volume.id)
