
class SecurityGroupHelper(AWSHelper):
    "modular and convergent security groups"
    # TODO compare with https://gist.github.com/steder/1498451 for better convergence

    def __init__(self, heet, name, description, rules):
        self.heet = heet
        self.name = name
        self.description = description
        self.rules = rules
        # TODO vpc_id option
        self.conn = boto.ec2.connect_to_region(
            heet.get_region(),
            aws_access_key_id=heet.access_key_id,
            aws_secret_access_key=heet.secret_access_key)
        heet.add_resource(self)

    def __str__(self):
        return "SecurityGroup %s" % self.name

    def get_resource_object(self):
        for group in self.conn.get_all_security_groups():
            if group.name == self.name:
                return group
        return None

    def converge(self):
        # TODO support converging rule changes
        if self.get_resource_object():
            return
        self.heet.logger.info("creating %s" % self)
        group = self.conn.create_security_group(self.name, self.description)
        for rule in self.rules:
            self.heet.logger.info("authorizing %s on %s" % (rule, self))
            group.authorize(
                ip_protocol=rule['ip_protocol'],
                from_port=rule['from_port'],
                to_port=rule['to_port'],
                cidr_ip=rule['cidr_ip']
            )

    def destroy(self):
        if not self.get_resource_object():
            return
        self.heet.logger.info("deleting SecurityGroup record %s" % (self.name))
        while True:
            try:
                self.conn.delete_security_group(name=self.name)
                return
            except:
                # instances may still be using this group
                self.heet.logger.debug("unable to delete %s just yet. will try again..." % (self.name))
                time.sleep(3)
