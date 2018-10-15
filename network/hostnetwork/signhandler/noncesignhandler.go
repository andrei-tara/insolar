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

package signhandler

import (
	"crypto/ecdsa"

	"github.com/insolar/insolar/core"
	ecdsa2 "github.com/insolar/insolar/cryptohelpers/ecdsa"
	"github.com/insolar/insolar/log"
	"github.com/insolar/insolar/network/hostnetwork/id"
	"github.com/pkg/errors"
)

// UncheckedNodes is a map of not authorized nodes.
type UncheckedNode struct {
	Ref   core.RecordRef
	Nonce []byte
}

// NonceSignHandler is a component which signs and check authorization nonce.
type NonceSignHandler struct {
	// TODO: add old unchecked nodes cleaner.
	uncheckedNodes map[string]UncheckedNode
	privateKey     *ecdsa.PrivateKey
}

// NewSignHandler creates a new sign handler.
func NewSignHandler(key *ecdsa.PrivateKey) *NonceSignHandler {
	return &NonceSignHandler{privateKey: key, uncheckedNodes: make(map[string]UncheckedNode)}
}

// AddUncheckedNode adds a new node to authorization.
func (handler *NonceSignHandler) AddUncheckedNode(hostID id.ID, nonce []byte, ref core.RecordRef) {
	unchecked := UncheckedNode{Ref: ref, Nonce: nonce}
	handler.uncheckedNodes[hostID.String()] = unchecked
}

// SignedNonceIsCorrect checks a nonce sign.
func (handler *NonceSignHandler) SignedNonceIsCorrect(coordinator core.NetworkCoordinator, hostID id.ID, signedNonce []byte) bool {
	if unchecked, ok := handler.uncheckedNodes[hostID.String()]; ok {
		key, _, err := coordinator.Authorize(unchecked.Ref, unchecked.Nonce, signedNonce)
		if err != nil {
			log.Error(err)
			log.Debug(hostID.String() + " failed to authorize")
			return false
		}
		log.Debug("authorized node ID: " + key)
		return true
	}
	return false
}

// SignNonce sign a nonce.
func (handler *NonceSignHandler) SignNonce(nonce []byte) ([]byte, error) {
	sign, err := ecdsa2.Sign(nonce, handler.privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign a message")
	}
	return sign, nil
}

// GetPrivateKey returns a private key.
func (handler *NonceSignHandler) GetPrivateKey() *ecdsa.PrivateKey {
	return handler.privateKey
}
