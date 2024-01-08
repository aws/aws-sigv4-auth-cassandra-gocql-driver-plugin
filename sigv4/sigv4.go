/*
 *  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

// provides sigv4 extensions to connect to Amazon Keyspaces
package sigv4

import (
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sigv4-auth-cassandra-gocql-driver-plugin/sigv4/internal"
	"github.com/gocql/gocql"
)

type SigV4Credentials struct {
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
}

// Callback used to retrieve V4 credentials, can be used with refreshable credentials
type SigV4CredentialsCallback func() (SigV4Credentials, error)

// Authenticator for AWS Integration
// these are exposed publicly to allow for easy initialization and go standard changing after the fact.
type AwsAuthenticator struct {
	Region              string
	AccessKeyId         string
	SecretAccessKey     string
	SessionToken        string
	CredentialsCallback SigV4CredentialsCallback
	currentTime         time.Time // this is mainly used for testing and not exposed
}

// initializes authenticator with credentials loaded from AWS SDK's default credential provider chain.
// region can be specified though environment variable or configuration.
func NewAwsAuthenticator() AwsAuthenticator {
	sess := session.Must(session.NewSession())
	region := sess.Config.Region
	creds, _ := sess.Config.Credentials.Get()

	return AwsAuthenticator{
		Region:          *region,
		AccessKeyId:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken}
}

// initializes authenticator with credentials loaded from AWS SDK's default credential provider chain.
// region is accepted as an argument.
func NewAwsAuthenticatorWithRegion(region string) AwsAuthenticator {
	sess := session.Must(session.NewSession())
	creds, _ := sess.Config.Credentials.Get()

	return AwsAuthenticator{
		Region:          region,
		AccessKeyId:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken}
}

// initializes authenticator with the provided region and credentials callback
func NewAwsAuthenticatorWithCredentialCallback(region string, callback SigV4CredentialsCallback) AwsAuthenticator {
	return AwsAuthenticator{
		Region:              region,
		CredentialsCallback: callback}
}

func (p AwsAuthenticator) Challenge(req []byte) ([]byte, gocql.Authenticator, error) {
	var resp []byte = []byte("SigV4\000\000")

	// copy these rather than use a reference due to how gocql creates connections (it's just
	// safer if everything is a fresh copy).
	auth := signingAuthenticator{region: p.Region,
		accessKeyId:         p.AccessKeyId,
		secretAccessKey:     p.SecretAccessKey,
		sessionToken:        p.SessionToken,
		credentialsCallback: p.CredentialsCallback,
		currentTime:         p.currentTime}
	return resp, auth, nil
}

func (p AwsAuthenticator) Success(data []byte) error {
	return nil
}

// this is the internal private authenticator we actually use
type signingAuthenticator struct {
	region              string
	accessKeyId         string
	secretAccessKey     string
	sessionToken        string
	credentialsCallback SigV4CredentialsCallback
	currentTime         time.Time
}

func (p signingAuthenticator) Challenge(req []byte) ([]byte, gocql.Authenticator, error) {
	nonce, err := internal.ExtractNonce(req)
	if err != nil {
		return nil, nil, err
	}

	// init the time if not provided.
	var t time.Time = p.currentTime
	if t.IsZero() {
		t = time.Now().UTC()
	}

	accessKeyId := p.accessKeyId
	secretAccessKey := p.secretAccessKey
	sessionToken := p.sessionToken
	if p.credentialsCallback != nil {
		credentials, err := p.credentialsCallback()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to retrieve AWS credentials: %w", err)
		}
		accessKeyId = credentials.AccessKeyId
		secretAccessKey = credentials.SecretAccessKey
		sessionToken = credentials.SessionToken
	}

	signedResponse := internal.BuildSignedResponse(p.region, nonce, accessKeyId,
		secretAccessKey, sessionToken, t)

	// copy this to a sepearte byte array to prevent some slicing corruption with how the framer object works
	resp := make([]byte, len(signedResponse))
	copy(resp, []byte(signedResponse))

	return resp, nil, nil
}

func (p signingAuthenticator) Success(data []byte) error {
	return nil
}
