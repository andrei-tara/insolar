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

package pulsar

import (
	"github.com/insolar/insolar/core"
)

type Payload struct {
	PublicKey string
	Signature []byte
	Body      interface{}
}

type HandshakePayload struct {
	Entropy core.Entropy
}

type GetLastPulsePayload struct {
	core.Pulse
}

type EntropySignaturePayload struct {
	PulseNumber core.PulseNumber
	Signature   []byte
}

type EntropyPayload struct {
	PulseNumber core.PulseNumber
	Entropy     core.Entropy
}

type VectorPayload struct {
	PulseNumber core.PulseNumber
	Vector      map[string]*BftCell
}

type PulsePayload struct {
	Pulse core.Pulse
}
