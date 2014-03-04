class GSLBHelper(AWSHelper):
    """modular and convergent weighted+healthchecked dns records. AFAIK, boto 2.21 does not support creating records with healthchecks, so shell out to aws"""

    def __init__(self, heet, name, target, **kwargs):
        self.heet = heet
        # normalize name to have trailing '.'
        self.name = name.rstrip('.') + '.'
        self.target = target
        self.healthcheck_path = self.heet.get_value('healthcheck_path', kwargs, default='/')
        self.healthcheck_port = self.heet.get_value('healthcheck_port', kwargs, default=80)
        self.ttl = self.heet.get_value('ttl', kwargs, default=300)
        self.zone_id = self.heet.get_value('zone_id', required=True)
        heet.add_resource(self)

    def __str__(self):
        return "GSLB %s" % self.name

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
            output = self.heet.exec_awscli(cmd)
        except Exception:
            self.heet.logger.debug("healthcheck %s may not have existed" % healthcheck_id)


