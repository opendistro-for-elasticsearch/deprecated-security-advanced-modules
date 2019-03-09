# Open Distro For Elasticsearch Security Advanced Modules

The Open Distro For Elasticsearch Security Advanced Modules builds on Open Distro for Elasticsearch Security and Open Distro for Elasticsearch Security-SSL to provide additional advanced features for securing your cluster. 

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

This package is organized into subprojects, most of which contribute JARs to the top-level plugin in the security subproject. All subprojects in this package use the Maven build system. Maven comes with excellent documentation that should be your first stop when trying to figure out how to operate or modify the build.

### Building from the command line
This project has a dependency on [security-parent][opendistro-elasticsearch-security-ssl] and [opendistro-elasticsearch-security] projects.You will have to build these projects  via maven (mvn clean install) first before attempting to build this package.

To try out the build, issue the following at the command line:

 1.` mvn compile`

This will run Maven, telling it to execute the compile goal. When it’s finished, you should find the compiled .class files in the target/classes directory.

The package goal will compile your Java code, run any tests, and finish by packaging the code up in a JAR file within the target directory.

2. `mvn package`

The test goal runs all the unit tests in the package

3. `mvn test`

## Debugging

Please refer to the well documented instructions provided by popular IDEs like Intellij and Eclipse on how to setup a debugger to debug code/test failures.

# License

This code is licensed under the [Apache License, Version 2.0](URL to license file).
