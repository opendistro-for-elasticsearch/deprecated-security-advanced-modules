[![CI](https://github.com/opendistro-for-elasticsearch/security-advanced-modules/workflows/CI/badge.svg?branch=master)](https://github.com/opendistro-for-elasticsearch/security-advanced-modules/actions)

# Open Distro For Elasticsearch Security Advanced Modules

The Open Distro For Elasticsearch Security Advanced Modules builds on Open Distro for Elasticsearch Security to provide additional advanced features for securing your cluster. 

## Note:

* **Deprecated as of Opendistro version 1.4**

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

## Custom CI build for testing

This project is dependent on [security-parent](https://github.com/opendistro-for-elasticsearch/security-parent) repository and [security](https://github.com/opendistro-for-elasticsearch/security) repository.
By default the Github Actions CI workflow checks out the master branch of both the repos.
In order to point to a different repository/fork/branch/tag for testing a pull request, please update `repository` and `ref` inputs of the respective checkout actions in the [ci.yml](.github/workflows/ci.yml) file. Here is a sample which uses `opendistro-1.3` branch of `security-parent` project during building.

```
    - name: Checkout security-parent
      uses: actions/checkout@v1
      with:
        repository: opendistro-for-elasticsearch/security-parent
        ref: refs/heads/opendistro-1.3
```

## Debugging

Please refer to the well documented instructions provided by popular IDEs like Intellij and Eclipse on how to setup a debugger to debug code/test failures.


## License

This code is licensed under the Apache 2.0 License. 

## Copyright

Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.

