# IMPORTANT: Latest Version

The current version is 1.0.0. Please see the [changelog](./CHANGELOG.md) for details on version history.

# What

This package implements an authentication plugin for the open-source [Gocql Driver](https://github.com/gocql/gocql) for Apache Cassandra. The driver enables you to add authentication information to your API requests using the AWS Signature Version 4 Process (SigV4). Using the plugin, you can provide users and applications short-term credentials to access Amazon Keyspaces (for Apache Cassandra) using AWS Identity and Access Management (IAM) users and roles.

The plugin depends on the AWS SDK for Go. It uses the default credential provider chain to obtain credentials.

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

Amazon Keyspaces requires the use of Transport Layer Security (TLS) to help secure connections with clients. To connect to Amazon Keyspaces using TLS, you need to download an Amazon digital certificate and configure the Go driver to use TLS.

Download the Starfield digital certificate using the following command and save sf-class2-root.crt locally or in your home directory.

```
curl https://certs.secureserver.net/repository/sf-class2-root.crt -O
```

## Region Configuration

Before you can start using the plugin, you must configure the AWS Region that the plugin will use when authenticating.  This is required because SigV4 signatures are Region-specific.  For example, if you are connecting to the `cassandra.us-east-2.amazonaws.com` endpoint,  the Region must be `us-east-2`.  For a list of available AWS Regions and endpoints, see [Service Endpoints for Amazon Keyspaces](https://docs.aws.amazon.com/keyspaces/latest/devguide/programmatic.endpoints.html).

You can specify the Region using one of the following four methods:

* Environment Variable
* Configuration
* Function Argument

### Environment Variable
You can use the `AWS_REGION` environment variable to match the endpoint that you are communicating with by setting it as part of your application start-up, as follows.

```
$ export AWS_Region=us-east-1
```

### Function Argument

One of the functions takes a String representing the Region as an argument, that will be used for that instance.

```
func NewAwsAuthenticatorWithRegion(region string) AwsAuthenticator {

}
```

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
