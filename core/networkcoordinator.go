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

package core

// NetworkCoordinator encapsulates logic of network configuration
type NetworkCoordinator interface {
	// Authorize authorizes node by verifying it's signature
	Authorize(nodeRef RecordRef, seed []byte, signatureRaw []byte) (string, NodeRole, error)
	// RegisterNode registers node in nodedomain
	RegisterNode(publicKey string, role string) (*RecordRef, error)
	// WriteActiveNodes write active nodes to ledger
	WriteActiveNodes(number PulseNumber, activeNodes []*ActiveNode) error
}
