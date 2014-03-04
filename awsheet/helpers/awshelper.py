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

class AWSHelper(object):
    "modular and convergent AWS Resources superclass"

    def __str__(self):
        return str(type(self))

    def post_init_hook(self):
        self.heet.logger.debug("no defined method post_init_hook for %s" % type(self))

    def post_converge_hook(self):
        self.heet.logger.debug("no defined method post_converge_hook for %s" % type(self))

    def pre_destroy_hook(self):
        self.heet.logger.debug("no defined method pre_destroy_hook for %s" % type(self))

    def get_cname_target(self):
        raise Exception("no cname target defined for %s" % self)


