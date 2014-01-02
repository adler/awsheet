
## AWSHeet

* automatically provision and configure AWS resources
* create equivalent stacks in production, staging and testing environments
* build your own scripts based on AWSHeet's idempotent primitives
* designed to be extensible
* delete/terminate all resources on demand

### How we use it
* create CloudFormation stacks and use the "outputs" (e.g. new security group) to provision more AWS resources
* set unique Name tag according to our convention and create a CNAME to the instance (e.g. "production-www-8-25.sub.domain.tld")
* set a custom tag that includes environment and role (so that ansible can deploy code to all with a tag "production--www" or "staing--app2")
* store role definition and environment in user_data so puppet can find it
* provision 8 xlarge instances in prod but only 1 medium in staging
* create an "indexed" CNAME with a predictable value (e.g. "production-www-01.sub.domain.tld")
