package socks5

import (
	"io"
	"log/slog"
	"net"

	"github.com/VanO219/errors"
)

// Connect remote conn which u want to connect with your dialer
// Error or OK both replied.
func (r *Request) Connect(w io.Writer) (rc net.Conn, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.Request.Connect()")
	}()

	slog.Debug("Connecting to address", slog.String("address", r.Address()))

	rc, err = DialTCP("tcp", "", r.Address())
	if err != nil {
		var p *Reply
		if r.Atyp == ATYPIPv4 || r.Atyp == ATYPDomain {
			p = NewReply(RepHostUnreachable, ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = NewReply(RepHostUnreachable, ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err := p.WriteTo(w); err != nil {
			return nil, errors.Wrap(err, "failed to write reply")
		}
		return nil, errors.Wrap(err, "failed to dial TCP")
	}

	a, addr, port, err := ParseAddress(rc.LocalAddr().String())
	if err != nil {
		rc.Close()
		var p *Reply
		if r.Atyp == ATYPIPv4 || r.Atyp == ATYPDomain {
			p = NewReply(RepHostUnreachable, ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = NewReply(RepHostUnreachable, ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err := p.WriteTo(w); err != nil {
			return nil, errors.Wrap(err, "failed to write reply")
		}
		return nil, errors.Wrap(err, "failed to parse address")
	}

	if a == ATYPDomain {
		addr = addr[1:]
	}

	p := NewReply(RepSuccess, a, addr, port)
	if _, err := p.WriteTo(w); err != nil {
		rc.Close()
		return nil, errors.Wrap(err, "failed to write success reply")
	}

	return rc, nil
}
