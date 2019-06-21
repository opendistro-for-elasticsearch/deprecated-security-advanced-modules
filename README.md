# Open Distro For Elasticsearch Security Advanced Modules

The Open Distro For Elasticsearch Security Advanced Modules builds on Open Distro for Elasticsearch Security to provide additional advanced features for securing your cluster. 

## Highlights

* Active Directory and LDAP Authentication/Authorization
* Kerberos/SPNEGO Authentication/Authorization
* JSON Web Token (JWT) Authentication/Authorization
* Document level security
* Field level security
* Audit logging with multiple audit log storage types
* Security configuration REST API
* Kibana multi tenancy

# Technical documentation

Please see our [technical documentation](https://opendistro.github.io/for-elasticsearch-docs/) for installation and configuration instructions.

# Developer setup, build, and run steps


## Setup

1. Check out this package from version control.
1. Launch Intellij IDEA, choose **Import Project**,  select the root of this package and import it as maven project. 
1. To build from the command line, set `JAVA_HOME` to point to a JDK >=11 before running `mvn`.


## Build

* Source build instructions can be found here : 

https://github.com/opendistro-for-elasticsearch/security-parent/blob/master/README.md


## Debugging

Please refer to the well documented instructions provided by popular IDEs like Intellij and Eclipse on how to setup a debugger to debug code/test failures.


## License

This code is licensed under the Apache 2.0 License. 

## Copyright

Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.

