## AWSHeet

AWSHeet is a lightweight python library that helps you provision all
your AWS resources.

* automatically provision and configure AWS resources (uses boto and awscli internally)
* create *equivalent* stacks in production, staging and testing environments
* build your own scripts based on AWSHeet's idempotent primitives
* extend AWSHeet with your own custom business logic
* clean up all resources on demand (terminate instances, delete Route53 records, etc)

The goal is to support continous delivery by having *all* your
infrastructure as code. This code needs to be able to safely and
reliably recreate your entire operating environments.

*AWSHeet is currently an alpha-stage project. The APIs are not stable, yet.*

### simple-demo.py

````
import awsheet
heet = awsheet.AWSHeet(
     { 'ami' : 'ami-a73264ce' }
)
awsheet.InstanceHelper(heet=heet, role='demo')
````
````
# provision the demo instance by running the script
$ ./simple-demo.py --environment staging
2014-01-14 09:11:33,025 - awsheet.core - INFO - provisioning ec2 instance type t1.micro for role=demo and environment=staging
2014-01-14 09:12:33,044 - awsheet.core - INFO - the following instance is ready 'ec2-23-22-57-89.compute-1.amazonaws.com'

# run the idempotent script again, which has no side effects
$ ./simple-demo.py --environment staging
2014-01-14 09:12:37,115 - awsheet.core - INFO - the following instance is ready 'ec2-23-22-57-89.compute-1.amazonaws.com'

# run the script with the --destory flag to terminate the instance
$ ./simple-demo.py --environment staging --destroy
You have asked to destroy the following resources from [ simple-demo / staging ]:

 * Instance simple-demo/staging/v=0/ami-a73264ce/t1.micro/index=1/demo

Are you sure? y/N: y
2014-01-14 09:12:47,409 - awsheet.core - INFO - terminating Instance:i-22f62f0c
2014-01-14 09:12:47,697 - awsheet.core - INFO - all AWS resources in [ simple-demo / staging ] are destroyed
````

### How does AWSHeet compare to boto or awscli?

AWSHeet is built with boto and awscli but provides a slightly higher
level of abstraction. This additional logic allows you to not only
build repeatable infrastructure, but automatically tear it down, too.

When you provision resources With AWSHeet you can specify which
"environment" (e.g. staging). AWSHeet will internally namespace the
resources to keep them separate. By enforcing this standard in a
consistent and automatic way, you get confidence that staging matches
production.

AWSHeet uses just a few simple patterns to support features like
environments and easy clean up. And because it's just python, not some
DSL, you always have quick access to the underlying libraries.

### How does AWSheet compare to CloudFormation?

AWSheet is pretty similar to CloudFormation and can sometimes replace
it, but it is designed to work together with CloudFormation. Some
reasons you might consider using CloudFormation:

 * and it is supported directly by Amazon
 * it supports a many types of resources
 * it has a declarative syntax so you don't have to manage ordering and dependencies
 * destroying "stacks" makes it easy to clean up

Some problems with CloudFormation are that:

 * coding in JSON is not an awesome experience
 * it is cumbersome to implement business logic or even basic preferences in the DSL
 * CloudFormation, in itself, does not support modular implementations

If you use CloudFormation together with AWSHeet, you get a good solution overall:

 * take advantage of CloudFormation as much as it makes sense
 * but avoid large, monolithic CloudFormation stacks
 * integrating one or more CloudFormation stacks is easy with AWSHeet
 * AWSHeet gives you vanilla python scripting for arbitrary logic

### AWSHeet allows us to ...
* create CloudFormation stacks and use the "outputs" (e.g. new security group) to provision more AWS resources
* set unique Name tag according to our convention and create a CNAME to the instance (e.g. "production-www-8-25.domain.tld")
* set a custom tag that includes environment and role (so that ansible can deploy code to all with a tag "production--www" or "staging--app2")
* store role definition and environment in user_data so puppet can find it
* provision 8 xlarge instances in prod but only 1 medium in staging
* create an "indexed" CNAME with a predictable value (e.g. "production-www-01.domain.tld")

### More Demos
Check out the demos to better understand how it works https://github.com/adler/awsheet-demos
