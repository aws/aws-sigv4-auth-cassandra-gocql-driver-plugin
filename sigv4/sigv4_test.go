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

package sigv4

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var stdNonce = []byte("nonce=91703fdc2ef562e19fbdab0f58e42fe5")

// We should switch to sigv4 when initially challenged
func TestShouldReturnSigV4iInitially(t *testing.T) {
	target := AwsAuthenticator{}
	resp, _, _ := target.Challenge(nil)

	assert.Equal(t, "SigV4\000\000", string(resp))
}

func TestShouldTranslate(t *testing.T) {
	target := buildStdTarget()
	_, challenger, _ := target.Challenge(nil)

	resp, _, _ := challenger.Challenge(stdNonce)
	expected := "signature=7f3691c18a81b8ce7457699effbfae5b09b4e0714ab38c1292dbdf082c9ddd87,access_key=UserID-1,amzdate=2020-06-09T22:41:51.000Z"
	assert.Equal(t, expected, string(resp))
}

func TestAssignFallbackRegionEnvironmentVariable(t *testing.T) {
	os.Setenv("AWS_DEFAULT_REGION", "us-west-2")
	os.Setenv("AWS_REGION", "us-east-2")

	defaultRegionTarget := NewAwsAuthenticator()

	assert.Equal(t, "us-west-2", defaultRegionTarget.Region)

	os.Unsetenv("AWS_DEFAULT_REGION")

	regionTarget := NewAwsAuthenticator()

	assert.Equal(t, "us-east-2", regionTarget.Region)

	os.Unsetenv("AWS_REGION")
}

func TestNewAwsAuthenticatorWithRegion(t *testing.T) {
	region := "us-east-2"

	authenticator := NewAwsAuthenticatorWithRegion(region)

	assert.Equal(t, region, authenticator.Region)
}

func buildStdTarget() *AwsAuthenticator {
	target := AwsAuthenticator{
		Region:          "us-west-2",
		AccessKeyId:     "UserID-1",
		SecretAccessKey: "UserSecretKey-1"}
	target.currentTime, _ = time.Parse(time.RFC3339, "2020-06-09T22:41:51Z")
	return &target
}

func TestCallback(t *testing.T) {
	callback := func() (SigV4Credentials, error) {
		return SigV4Credentials{
			AccessKeyId:     "UserID-1",
			SecretAccessKey: "UserSecretKey-1",
		}, nil
	}
	target := NewAwsAuthenticatorWithCredentialCallback("us-west-2", callback)
	target.currentTime, _ = time.Parse(time.RFC3339, "2020-06-09T22:41:51Z")

	_, challenger, _ := target.Challenge(nil)

	resp, _, _ := challenger.Challenge(stdNonce)
	expected := "signature=7f3691c18a81b8ce7457699effbfae5b09b4e0714ab38c1292dbdf082c9ddd87,access_key=UserID-1,amzdate=2020-06-09T22:41:51.000Z"
	assert.Equal(t, expected, string(resp))
}

func TestCallbackError(t *testing.T) {
	callback := func() (SigV4Credentials, error) {
		return SigV4Credentials{}, fmt.Errorf("bad error")
	}
	target := NewAwsAuthenticatorWithCredentialCallback("us-west-2", callback)
	target.currentTime, _ = time.Parse(time.RFC3339, "2020-06-09T22:41:51Z")

	_, challenger, _ := target.Challenge(nil)
	_, _, err := challenger.Challenge(stdNonce)
	assert.Error(t, err, "failed to retrieve AWS credentials: bad error")
}
