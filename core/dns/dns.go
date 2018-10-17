/*
 *    Copyright 2018 Insolar
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package dns

import (
	"net"
	"strconv"
	"strings"
)

// GetIpFromDomain returns IP address string from domain.
func GetIpFromDomain(domain string) (string, error) {
	woPort := strings.Split(domain, ":")
	address := woPort[0]
	port := woPort[1]

	ips, err := net.LookupIP(address)
	if err != nil {
		return "", err
	}

	return ips[0].String() + ":" + port, nil
}

// IsDomain return true if input arg is domain address.
func IsDomain(address string) bool {
	tmp := strings.Split(address, ".")
	for _, oct := range tmp {
		if _, err := strconv.Atoi(oct); err != nil {
			return true
		}
	}
	return false
}