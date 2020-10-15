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

package internal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// extract the nonce from a request payload
// needed for calls from payload returned by Amazon Keyspaces.
func ExtractNonce(req []byte) (string, error) {
	text := string(req)
	if !strings.HasPrefix(text, "nonce=") {
		return "", errors.New("request does not contain nonce property")
	}
	nonce := strings.Split(text, "nonce=")[1]

	return nonce, nil
}

// Convert time to an aws credential timestamp
// such as 2020-06-09T22:41:51.000Z -> '20200609'
func toCredDateStamp(t time.Time) string {
	return fmt.Sprintf("%d%02d%02d", t.Year(), t.Month(), t.Day())
}

// compute the scope to be used in the request
func computeScope(t time.Time, region string) string {
	a := []string{
		toCredDateStamp(t),
		region,
		"cassandra",
		"aws4_request"}
	return strings.Join(a, "/")
}

func formCanonicalRequest(accessKeyId string, scope string, t time.Time, nonce string) string {
	nonceHash := sha256.Sum256([]byte(nonce))
	headers := []string{
		"X-Amz-Algorithm=AWS4-HMAC-SHA256",
		fmt.Sprintf("X-Amz-Credential=%s%%2F%s", accessKeyId, url.QueryEscape(scope)),
		fmt.Sprintf("X-Amz-Date=%s", url.QueryEscape(t.Format("2006-01-02T15:04:05.000Z"))),
		"X-Amz-Expires=900"}
	sort.Strings(headers)
	queryString := strings.Join(headers, "&")

	return fmt.Sprintf("PUT\n/authenticate\n%s\nhost:cassandra\n\nhost\n%s", queryString, hex.EncodeToString(nonceHash[:]))
}

// applies hmac with given string
// useful as our protocol requires lots of iterative hmacs
func applyHmac(data string, hashSecret []byte) []byte {
	h := hmac.New(sha256.New, hashSecret)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func deriveSigningKey(secret string, t time.Time, region string) []byte {
	// we successively apply the hmac secret in multiple iterations rather then simply
	// write it once (as per the Amazon Keyspaces protocol)
	s := "AWS4" + secret
	h := applyHmac(toCredDateStamp(t), []byte(s))
	h = applyHmac(region, h)
	h = applyHmac("cassandra", h)
	h = applyHmac("aws4_request", h)
	return h
}

func createSignature(canonicalRequest string, t time.Time, signingScope string, signingKey []byte) []byte {
	digest := sha256.Sum256([]byte(canonicalRequest))
	s := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", t.Format("2006-01-02T15:04:05.000Z"), signingScope, hex.EncodeToString(digest[:]))

	return applyHmac(s, []byte(signingKey))
}

// creates response that can be sent for a SigV4 challenge
// this includes both the signature and the metadata supporting signature.
func BuildSignedResponse(region string, nonce string, accessKeyId string, secret string, sessionToken string, t time.Time) string {
	scope := computeScope(t, region)
	canonicalRequest := formCanonicalRequest(accessKeyId, scope, t, nonce)
	signingKey := deriveSigningKey(secret, t, region)

	signature := createSignature(canonicalRequest, t, scope, signingKey)

	result := fmt.Sprintf("signature=%s,access_key=%s,amzdate=%s", hex.EncodeToString(signature), accessKeyId, t.Format("2006-01-02T15:04:05.000Z"))

	if sessionToken != "" {
		result += fmt.Sprintf(",session_token=%s", sessionToken)
	}
	return result
}
