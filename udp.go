package socks5

import (
	"bytes"
	"log/slog"
	"net"

	"github.com/VanO219/errors"
)

// UDP remote conn which u want to connect with your dialer.
// Error or OK both replied.
// Addr can be used to associate TCP connection with the coming UDP connection.
func (r *Request) UDP(c net.Conn, serverAddr net.Addr) (clientAddr net.Addr, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.Request.UDP()")
	}()

	if bytes.Compare(r.DstPort, []byte{0x00, 0x00}) == 0 {
		// If the requested Host/Port is all zeros, the relay should simply use the Host/Port that sent the request.
		// https://stackoverflow.com/questions/62283351/how-to-use-socks-5-proxy-with-tidudpclient-properly
		clientAddr, err = net.ResolveUDPAddr("udp", c.RemoteAddr().String())
	} else {
		clientAddr, err = net.ResolveUDPAddr("udp", r.Address())
	}
	if err != nil {
		if err := r.ReplyWithError(c, RepHostUnreachable); err != nil {
			return nil, errors.Wrap(err, "failed to write reply")
		}
		return nil, errors.Wrap(err, "failed to resolve UDP address")
	}

	slog.Debug("Client wants to start UDP talk", slog.String("address", clientAddr.String()))

	a, addr, port, err := ParseAddress(serverAddr.String())
	if err != nil {
		if err := r.ReplyWithError(c, RepHostUnreachable); err != nil {
			return nil, errors.Wrap(err, "failed to write reply")
		}
		return nil, errors.Wrap(err, "failed to parse server address")
	}
	if a == ATYPDomain {
		addr = addr[1:]
	}
	p := NewReply(RepSuccess, a, addr, port)
	if _, err := p.WriteTo(c); err != nil {
		return nil, errors.Wrap(err, "failed to write success reply")
	}

	return clientAddr, nil
}
