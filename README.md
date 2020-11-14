# IMPORTANT: Latest Version

The current version is 1.0.0. Please see the [changelog](./CHANGELOG.md) for details on version history.

# What

This package implements an authentication plugin for the open-source [Gocql Driver](https://github.com/gocql/gocql) for Apache Cassandra. The driver enables you to add authentication information to your API requests using the AWS Signature Version 4 Process (SigV4). Using the plugin, you can provide users and applications short-term credentials to access Amazon Keyspaces (for Apache Cassandra) using AWS Identity and Access Management (IAM) users and roles.

You must specify the service endpoint to use for the connection. You can provide the Region in the constructor programmatically, via the `AWS_DEFAULT_REGION` environment variable.

The full documentation for the plugin is available at AWS Docs:
[Creating Credentials to Access Amazon Keyspaces](https://docs.aws.amazon.com/keyspaces/latest/devguide/programmatic.credentials.html#programmatic.credentials.SigV4_KEYSPACES)

# Using the Plugin
The following sections describe how to use the authentication plugin for the open-source gocql Driver for Cassandra to access Amazon Keyspaces.

To install the plugin:
```bash
$ go get github.com/aws/aws-sigv4-auth-cassandra-gocql-driver-plugin
```

## SSL Configuration

The first step is to get an Amazon digital certificate to encrypt your connections using Transport Layer Security (TLS).  The Gocql driver must use an SSL trust store so that the client SSL engine can validate the Amazon Keyspaces certificate on connection.

To use the trust store and create a certificate, see  
[Using a Cassandra Java Client Driver to Access Amazon Keyspaces Programmatically](https://docs.aws.amazon.com/keyspaces/latest/devguide/programmatic.drivers.html#using_java_driver).

## Region Configuration

Before you can start using the plugin, you must configure the AWS Region that the plugin will use when authenticating.  This is required because SigV4 signatures are Region-specific.  For example, if you are connecting to the `cassandra.us-east-2.amazonaws.com` endpoint,  the Region must be `us-east-2`.  For a list of available AWS Regions and endpoints, see [Service Endpoints for Amazon Keyspaces](https://docs.aws.amazon.com/keyspaces/latest/devguide/programmatic.endpoints.html).

You can specify the Region using one of the following four methods:

* Environment Variable
* Configuration

## Environment Variables
The following values of AwsAuthenticator will be set from environment variables on initial new
  - Region: from environment variable AWS_DEFAULT_REGION, falling back to AWS_REGION
  - AccessKeyId: from environment variable AWS_ACCESS_KEY_ID
  - SecretAccessKey: from environment variable AWS_SECRET_ACCESS_KEY
  - SessionToken:  from environment variable AWS_SESSION_TOKEN

## How to use the Authentication Plugin

When using the open-source gocql driver, the connection to your Amazon Keyspaces endpoint is represented by the `Cluster` class.
Simply use AwsAuthenticator for the authenticator property of the cluster.

Here is a simple example of use:

```go
package main

import (
        "fmt"
        "github.com/aws/aws-sigv4-auth-cassandra-gocql-driver-plugin/sigv4"
        "github.com/gocql/gocql"
        "log"
)

func main() {
	// configuring the cluster options
	cluster := gocql.NewCluster("cassandra.us-west-2.amazonaws.com:9142")
	var auth sigv4.AwsAuthenticator = sigv4.NewAwsAuthenticator()
	auth.Region = "us-west-2"
	auth.AccessKeyId = "AKIAIOSFODNN7EXAMPLE"
	auth.SecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" 

	cluster.Authenticator = auth

	cluster.SslOpts = &gocql.SslOptions{
		CaPath: "/Users/user1/.cassandra/AmazonRootCA1.pem",
	}
	cluster.Consistency = gocql.LocalQuorum
	cluster.DisableInitialHostLookup = true

	session, err := cluster.CreateSession()
	if err != nil {
		fmt.Println("err>", err)
		return
	}
	defer session.Close()

	// doing the query
	var text string
	iter := session.Query("SELECT keyspace_name FROM system_schema.tables;").Iter()
	for iter.Scan(&text) {
		fmt.Println("keyspace_name:", text)
	}
	if err := iter.Close(); err != nil {
		log.Fatal(err)
	}
}
```

When using AwsAuthenticator from an AWS Lambda function, the Lambda runtimes will initialize all the needed environment variables.
All you need to do is assign the authenticator.

```go
	cluster.Authenticator = sigv4.NewAwsAuthenticator()
```
