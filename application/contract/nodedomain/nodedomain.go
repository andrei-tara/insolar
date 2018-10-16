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

package nodedomain

import (
	"github.com/insolar/insolar/application/proxy/noderecord"
	"github.com/insolar/insolar/core"
	"github.com/insolar/insolar/cryptohelpers/ecdsa"
	"github.com/insolar/insolar/logicrunner/goplugin/foundation"
)

// NodeDomain holds noderecords
type NodeDomain struct {
	foundation.BaseContract
}

// NewNodeDomain create new NodeDomain
func NewNodeDomain() *NodeDomain {
	return &NodeDomain{}
}

// RegisterNode registers node in system
func (nd *NodeDomain) RegisterNode(pk string, role string) (*core.RecordRef, error) {
	// TODO: what should be done when record already exists?
	newRecord := noderecord.NewNodeRecord(pk, role)
	if newRecord == nil {
		return nil, &foundation.Error{S: "[ RegisterNode ] bad role"}
	}
	record := newRecord.AsChild(nd.GetReference())
	ref := record.GetReference()
	return &ref, nil
}

func (nd *NodeDomain) getNodeRecord(ref core.RecordRef) *noderecord.NodeRecord {
	return noderecord.GetObject(ref)
}

// RemoveNode deletes node from registry
func (nd *NodeDomain) RemoveNode(nodeRef core.RecordRef) {
	node := nd.getNodeRecord(nodeRef)
	node.Destroy()
}

// IsAuthorized checks is signature correct
func (nd *NodeDomain) IsAuthorized(nodeRef core.RecordRef, seed []byte, signatureRaw []byte) error {
	nodeR := nd.getNodeRecord(nodeRef)
	ok, err := ecdsa.Verify(seed, signatureRaw, nodeR.GetPublicKey())
	if err != nil {
		return &foundation.Error{S: "[ IsAuthorized ] Problem with verifying signature: " + err.Error()}
	}
	if !ok {
		return &foundation.Error{S: "[ IsAuthorized ] Wrong signature: " + err.Error()}
	}

	return nil
}

// Authorize checks node and returns node info
func (nd *NodeDomain) Authorize(nodeRef core.RecordRef, seed []byte, signatureRaw []byte) (string, core.NodeRole, error) {
	nodeR := nd.getNodeRecord(nodeRef)
	role, pubKey := nodeR.GetRoleAndPublicKey()
	ok, err := ecdsa.Verify(seed, signatureRaw, pubKey)
	if err != nil {
		return "", core.RoleUnknown, &foundation.Error{S: "[ Authorize ] Problem with verifying of signature: " + err.Error()}
	}
	if !ok {
		return "", core.RoleUnknown, &foundation.Error{S: "[ Authorize ] Can't verify signature: " + err.Error()}
	}

	return pubKey, role, nil
}
