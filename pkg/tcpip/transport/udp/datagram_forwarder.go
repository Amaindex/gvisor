// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package udp

import (
	"math"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// DatagramForwarderHandler handles an incoming UDP datagram. Returning true
// marks the datagram as handled. Returning false marks the datagram as
// unhandled; the stack may send an ICMP port unreachable message.
type DatagramForwarderHandler func(*DatagramRequest) (handled bool)

// DatagramForwarder is a packet-level UDP forwarder for embedders.
//
// Unlike Forwarder, DatagramForwarder does not turn an incoming UDP packet into
// a connected endpoint. It exposes each packet as a datagram request so the
// embedder can apply its own forwarding, proxying, tunneling, or NAT policy.
//
// The canonical way of using it is to pass the DatagramForwarder's HandlePacket
// function to stack.SetTransportProtocolHandler.
type DatagramForwarder struct {
	handler DatagramForwarderHandler

	stack *stack.Stack
}

// NewDatagramForwarder allocates and initializes a new datagram forwarder.
func NewDatagramForwarder(s *stack.Stack, handler DatagramForwarderHandler) *DatagramForwarder {
	return &DatagramForwarder{
		stack:   s,
		handler: handler,
	}
}

// HandlePacket handles packets delivered to the datagram forwarder.
//
// This function is expected to be passed as an argument to the
// stack.SetTransportProtocolHandler function.
func (f *DatagramForwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	lengthValid, csumValid := validateDatagram(pkt)
	if !lengthValid {
		f.stack.Stats().UDP.MalformedPacketsReceived.Increment()
		f.stack.Stats().NICs.MalformedL4RcvdPackets.Increment()
		return true
	}
	if !csumValid {
		f.stack.Stats().UDP.ChecksumErrors.Increment()
		return true
	}

	req := &DatagramRequest{
		stack:    f.stack,
		id:       id,
		nicID:    pkt.NICID,
		netProto: pkt.NetworkProtocolNumber,
		payload:  payloadFromPacket(pkt),
	}
	return f.handler(req)
}

// DatagramRequest represents a UDP datagram received by a DatagramForwarder.
//
// DatagramRequest does not expose the packet buffer it was built from. Payload
// returns a copy of the UDP payload, and Source and Destination return the
// packet tuple observed by netstack.
type DatagramRequest struct {
	stack    *stack.Stack
	id       stack.TransportEndpointID
	nicID    tcpip.NICID
	netProto tcpip.NetworkProtocolNumber
	payload  []byte
}

// ID returns the 4-tuple (src address, src port, dst address, dst port) that
// represents the datagram.
func (r *DatagramRequest) ID() stack.TransportEndpointID {
	return r.id
}

// NetworkProtocol returns the network protocol of the datagram.
func (r *DatagramRequest) NetworkProtocol() tcpip.NetworkProtocolNumber {
	return r.netProto
}

// Payload returns a copy of the datagram payload.
func (r *DatagramRequest) Payload() []byte {
	return append([]byte(nil), r.payload...)
}

// Source returns the datagram source address.
func (r *DatagramRequest) Source() tcpip.FullAddress {
	return tcpip.FullAddress{
		NIC:  r.nicID,
		Addr: r.id.RemoteAddress,
		Port: r.id.RemotePort,
	}
}

// Destination returns the datagram destination address as observed by netstack.
func (r *DatagramRequest) Destination() tcpip.FullAddress {
	return tcpip.FullAddress{
		NIC:  r.nicID,
		Addr: r.id.LocalAddress,
		Port: r.id.LocalPort,
	}
}

// WriteDatagram writes a UDP datagram with explicit source and destination.
//
// If opts.NetProto is unspecified, the incoming datagram's network protocol is
// used. Route selection uses the same NIC rules as package-level WriteDatagram.
// Source addresses are validated by stack.FindRoute; embedders that need
// non-local source addresses must explicitly enable NIC spoofing. WriteDatagram
// does not create or register a UDP endpoint.
func (r *DatagramRequest) WriteDatagram(opts WriteDatagramOptions, payload []byte) tcpip.Error {
	if opts.NetProto == 0 {
		opts.NetProto = r.netProto
	}
	return WriteDatagram(r.stack, opts, payload)
}

// WriteDatagramOptions contains parameters for writing an explicit UDP
// datagram.
type WriteDatagramOptions struct {
	// NetProto is the network protocol used for the outgoing packet.
	NetProto tcpip.NetworkProtocolNumber

	// NIC constrains route selection to a NIC. If NIC is zero, WriteDatagram
	// falls back to Destination.NIC.
	NIC tcpip.NICID

	// Source is the outgoing UDP source. Source.NIC is not used for route
	// selection; use NIC to constrain the outgoing NIC.
	Source tcpip.FullAddress

	// Destination is the outgoing UDP destination. Destination.NIC is used for
	// route selection if NIC is zero.
	Destination tcpip.FullAddress
}

// WriteDatagram writes a UDP datagram with explicit source and destination.
//
// If opts.NIC is zero, WriteDatagram falls back to opts.Destination.NIC. If
// both are zero, route selection is unconstrained by NIC. Source addresses are
// validated by stack.FindRoute; embedders that need non-local source addresses
// must explicitly enable NIC spoofing. WriteDatagram does not create or
// register a UDP endpoint, and emitted packets do not carry ordinary socket
// owner context.
func WriteDatagram(s *stack.Stack, opts WriteDatagramOptions, payload []byte) tcpip.Error {
	return writeDatagram(s, opts, payload)
}

func payloadFromPacket(pkt *stack.PacketBuffer) []byte {
	buf := pkt.Data().ToBuffer()
	defer buf.Release()
	payload := buf.Flatten()

	udp := header.UDP(pkt.TransportHeader().Slice())
	payloadLen := int(udp.Length()) - header.UDPMinimumSize
	if payloadLen < 0 {
		return nil
	}
	if payloadLen > len(payload) {
		payloadLen = len(payload)
	}
	return payload[:payloadLen]
}

func writeDatagram(s *stack.Stack, opts WriteDatagramOptions, payload []byte) tcpip.Error {
	if len(payload) > header.UDPMaximumPacketSize-header.UDPMinimumSize {
		return &tcpip.ErrMessageTooLong{}
	}
	missingSource := opts.Source.Addr == (tcpip.Address{}) || opts.Source.Port == 0
	missingDestination := opts.Destination.Addr == (tcpip.Address{}) || opts.Destination.Port == 0
	if missingSource || missingDestination || opts.NetProto == 0 {
		return &tcpip.ErrInvalidEndpointState{}
	}

	nicID := opts.NIC
	if nicID == 0 {
		nicID = opts.Destination.NIC
	}

	route, err := s.FindRoute(nicID, opts.Source.Addr, opts.Destination.Addr, opts.NetProto, false /* multicastLoop */)
	if err != nil {
		return err
	}
	defer route.Release()

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(route.MaxHeaderLength()) + header.UDPMinimumSize,
		Payload:            buffer.MakeWithData(append([]byte(nil), payload...)),
	})
	defer pkt.DecRef()

	udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	pkt.TransportProtocolNumber = ProtocolNumber

	length := uint16(pkt.Size())
	udp.Encode(&header.UDPFields{
		SrcPort: opts.Source.Port,
		DstPort: opts.Destination.Port,
		Length:  length,
	})

	if route.RequiresTXTransportChecksum() || opts.NetProto == header.IPv6ProtocolNumber {
		xsum := udp.CalculateChecksum(checksum.Combine(
			header.PseudoHeaderChecksum(ProtocolNumber, route.LocalAddress(), route.RemoteAddress(), length),
			pkt.Data().Checksum(),
		))
		if xsum != math.MaxUint16 {
			xsum = ^xsum
		}
		udp.SetChecksum(xsum)
	}

	if err := route.WritePacket(stack.NetworkHeaderParams{
		Protocol: ProtocolNumber,
		TTL:      route.DefaultTTL(),
		TOS:      stack.DefaultTOS,
	}, pkt); err != nil {
		s.Stats().UDP.PacketSendErrors.Increment()
		return err
	}

	s.Stats().UDP.PacketsSent.Increment()
	return nil
}
