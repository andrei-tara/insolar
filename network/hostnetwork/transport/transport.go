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

package transport

import (
	"github.com/insolar/insolar/configuration"
	"github.com/insolar/insolar/network/hostnetwork/connection"
	"github.com/insolar/insolar/network/hostnetwork/packet"
	"github.com/insolar/insolar/network/hostnetwork/relay"
	"github.com/insolar/insolar/network/hostnetwork/resolver"
	"github.com/pkg/errors"
)

// Transport is an interface for network transport.
type Transport interface {
	// SendRequest sends packet to destination. Sequence number is generated automatically.
	SendRequest(*packet.Packet) (Future, error)

	// SendResponse sends packet for request with passed request id.
	SendResponse(packet.RequestID, *packet.Packet) error

	// Start starts thread to listen incoming packets.
	Start() error

	// Stop gracefully stops listening.
	Stop()

	// Close disposing all transport underlying structures after stop are called.
	Close()

	// Packets returns channel to listen incoming packets.
	Packets() <-chan *packet.Packet

	// Stopped returns signal channel to support graceful shutdown.
	Stopped() <-chan bool

	// PublicAddress returns PublicAddress
	PublicAddress() string
}

// NewTransport creates new Transport with particular configuration
func NewTransport(cfg configuration.Transport, proxy relay.Proxy) (Transport, error) {
	conn, err := connection.NewConnectionFactory().Create(cfg.Address)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create connection")
	}

	publicAddress, err := createResolver(cfg.BehindNAT).Resolve(conn)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create resolver")
	}

	switch cfg.Protocol {
	case "UTP":
		return newUTPTransport(conn, proxy, publicAddress)
	case "KCP":
		return newKCPTransport(conn, proxy, publicAddress)
	default:
		return nil, errors.New("invalid transport configuration")
	}
}

func createResolver(stun bool) resolver.PublicAddressResolver {
	if stun {
		return resolver.NewStunResolver("")
	}
	return resolver.NewExactResolver()
}
