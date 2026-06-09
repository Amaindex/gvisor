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
		return true
	}
	if !csumValid {
		f.stack.Stats().UDP.ChecksumErrors.Increment()
		return true
	}

	req := &DatagramRequest{
		stack: f.stack,
		id:    id,
		pkt:   pkt.Clone(),
	}
	defer req.pkt.DecRef()
	return f.handler(req)
}

// DatagramRequest represents a UDP datagram received by a DatagramForwarder.
type DatagramRequest struct {
	stack *stack.Stack
	id    stack.TransportEndpointID
	pkt   *stack.PacketBuffer
}

// ID returns the 4-tuple (src address, src port, dst address, dst port) that
// represents the datagram.
func (r *DatagramRequest) ID() stack.TransportEndpointID {
	return r.id
}

// Payload returns a copy of the datagram payload.
func (r *DatagramRequest) Payload() []byte {
	buf := r.pkt.Data().ToBuffer()
	defer buf.Release()
	return buf.Flatten()
}

// Source returns the datagram source address.
func (r *DatagramRequest) Source() tcpip.FullAddress {
	return tcpip.FullAddress{
		NIC:  r.pkt.NICID,
		Addr: r.id.RemoteAddress,
		Port: r.id.RemotePort,
	}
}

// Destination returns the datagram destination address as observed by netstack.
func (r *DatagramRequest) Destination() tcpip.FullAddress {
	return tcpip.FullAddress{
		NIC:  r.pkt.NICID,
		Addr: r.id.LocalAddress,
		Port: r.id.LocalPort,
	}
}

// WriteBack writes a UDP datagram with an explicit source and destination.
//
// The datagram is written using the same network protocol as the incoming
// request. Source addresses are validated by stack.FindRoute; embedders that
// need non-local source addresses must explicitly enable NIC spoofing.
func (r *DatagramRequest) WriteBack(payload []byte, src, dst tcpip.FullAddress) tcpip.Error {
	return writeDatagram(r.stack, r.pkt.NetworkProtocolNumber, payload, src, dst)
}

func validateDatagram(pkt *stack.PacketBuffer) (lengthValid, csumValid bool) {
	hdr := header.UDP(pkt.TransportHeader().Slice())
	netHdr := pkt.Network()
	return header.UDPValid(
		hdr,
		func() uint16 { return pkt.Data().Checksum() },
		uint16(pkt.Data().Size()),
		pkt.NetworkProtocolNumber,
		netHdr.SourceAddress(),
		netHdr.DestinationAddress(),
		pkt.RXChecksumValidated)
}

func writeDatagram(s *stack.Stack, netProto tcpip.NetworkProtocolNumber, payload []byte, src, dst tcpip.FullAddress) tcpip.Error {
	if len(payload) > header.UDPMaximumPacketSize-header.UDPMinimumSize {
		return &tcpip.ErrMessageTooLong{}
	}
	if src.Port == 0 || dst.Port == 0 {
		return &tcpip.ErrInvalidEndpointState{}
	}

	nicID := dst.NIC
	if nicID == 0 {
		nicID = src.NIC
	}

	route, err := s.FindRoute(nicID, src.Addr, dst.Addr, netProto, false /* multicastLoop */)
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
		SrcPort: src.Port,
		DstPort: dst.Port,
		Length:  length,
	})

	if route.RequiresTXTransportChecksum() || netProto == header.IPv6ProtocolNumber {
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
