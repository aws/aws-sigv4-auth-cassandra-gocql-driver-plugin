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
	"os"
	"time"

	"github.com/aws/aws-sigv4-auth-cassandra-gocql-driver-plugin/sigv4/internal"
	"github.com/gocql/gocql"
)

// Authenticator for AWS Integration
// these are exposed publicly to allow for easy initialization and go standard changing after the fact.
type AwsAuthenticator struct {
	Region          string
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	currentTime     time.Time // this is mainly used for testing and not exposed
}

// looks up AWS_DEFAULT_REGION, and falls back to AWS_REGION for Lambda compatibility
func getRegionEnvironment() string {
	region := os.Getenv("AWS_DEFAULT_REGION")

	if len(region) == 0 {
		region = os.Getenv("AWS_REGION")
	}

	return region
}

// initializes authenticator with standard AWS CLI environment variables if they exist.
func NewAwsAuthenticator() AwsAuthenticator {
	return AwsAuthenticator{
		Region:          getRegionEnvironment(),
		AccessKeyId:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN")}
}

func (p AwsAuthenticator) Challenge(req []byte) ([]byte, gocql.Authenticator, error) {
	var resp []byte = []byte("SigV4\000\000")

	// copy these rather than use a reference due to how gocql creates connections (its just
	// safer if everything if a fresh copy).
	auth := signingAuthenticator{region: p.Region,
		accessKeyId:     p.AccessKeyId,
		secretAccessKey: p.SecretAccessKey,
		sessionToken:    p.SessionToken,
		currentTime:     p.currentTime}
	return resp, auth, nil
}

func (p AwsAuthenticator) Success(data []byte) error {
	return nil
}

// this is the internal private authenticator we actually use
type signingAuthenticator struct {
	region          string
	accessKeyId     string
	secretAccessKey string
	sessionToken    string
	currentTime     time.Time
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

	signedResponse := internal.BuildSignedResponse(p.region, nonce, p.accessKeyId,
		p.secretAccessKey, p.sessionToken, t)

	// copy this to a sepearte byte array to prevent some slicing corruption with how the framer object works
	resp := make([]byte, len(signedResponse))
	copy(resp, []byte(signedResponse))

	return resp, nil, nil
}

func (p signingAuthenticator) Success(data []byte) error {
	return nil
}
