
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


