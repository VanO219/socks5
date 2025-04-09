package socks5

import (
	"io"
	"log/slog"

	"github.com/VanO219/errors"
)

var (
	// ErrVersion is version error
	ErrVersion = errors.New("Invalid Version")
	// ErrUserPassVersion is username/password auth version error
	ErrUserPassVersion = errors.New("Invalid Version of Username Password Auth")
	// ErrBadRequest is bad request error
	ErrBadRequest = errors.New("Bad Request")
)

// NewNegotiationRequestFrom read negotiation requst packet from client
func NewNegotiationRequestFrom(r io.Reader) (nr *NegotiationRequest, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.NewNegotiationRequestFrom()")
	}()

	// memory strict
	bb := make([]byte, 2)
	if _, err := io.ReadFull(r, bb); err != nil {
		return nil, errors.Wrap(err, "failed to read version and methods count")
	}
	if bb[0] != Ver {
		return nil, ErrVersion
	}
	if bb[1] == 0 {
		return nil, ErrBadRequest
	}
	ms := make([]byte, int(bb[1]))
	if _, err := io.ReadFull(r, ms); err != nil {
		return nil, errors.Wrap(err, "failed to read methods")
	}

	slog.Debug("Got negotiation request",
		slog.Any("version", bb[0]),
		slog.Any("methods_count", bb[1]),
		slog.Any("methods", ms))

	return &NegotiationRequest{
		Ver:      bb[0],
		NMethods: bb[1],
		Methods:  ms,
	}, nil
}

// NewNegotiationReply return negotiation reply packet can be writed into client
func NewNegotiationReply(method byte) *NegotiationReply {
	return &NegotiationReply{
		Ver:    Ver,
		Method: method,
	}
}

// WriteTo write negotiation reply packet into client
func (r *NegotiationReply) WriteTo(w io.Writer) (n int64, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.NegotiationReply.WriteTo()")
	}()

	i, err := w.Write([]byte{r.Ver, r.Method})
	if err != nil {
		return 0, errors.Wrap(err, "failed to write negotiation reply")
	}

	slog.Debug("Sent negotiation reply",
		slog.Any("version", r.Ver),
		slog.Any("method", r.Method))

	return int64(i), nil
}

// NewUserPassNegotiationRequestFrom read user password negotiation request packet from client
func NewUserPassNegotiationRequestFrom(r io.Reader) (req *UserPassNegotiationRequest, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.NewUserPassNegotiationRequestFrom()")
	}()

	bb := make([]byte, 2)
	if _, err := io.ReadFull(r, bb); err != nil {
		return nil, errors.Wrap(err, "failed to read version and username length")
	}
	if bb[0] != UserPassVer {
		return nil, ErrUserPassVersion
	}
	if bb[1] == 0 {
		return nil, ErrBadRequest
	}
	ub := make([]byte, int(bb[1])+1)
	if _, err := io.ReadFull(r, ub); err != nil {
		return nil, errors.Wrap(err, "failed to read username and password length")
	}
	if ub[int(bb[1])] == 0 {
		return nil, ErrBadRequest
	}
	p := make([]byte, int(ub[int(bb[1])]))
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, errors.Wrap(err, "failed to read password")
	}

	slog.Debug("Got username/password negotiation request",
		slog.Any("version", bb[0]),
		slog.Any("username_length", bb[1]),
		slog.String("username", string(ub[:int(bb[1])])),
		slog.Any("password_length", ub[int(bb[1])]),
		slog.String("password", "[MASKED]"))

	return &UserPassNegotiationRequest{
		Ver:    bb[0],
		Ulen:   bb[1],
		Uname:  ub[:int(bb[1])],
		Plen:   ub[int(bb[1])],
		Passwd: p,
	}, nil
}

// NewUserPassNegotiationReply return negotiation username password reply packet can be writed into client
func NewUserPassNegotiationReply(status byte) *UserPassNegotiationReply {
	return &UserPassNegotiationReply{
		Ver:    UserPassVer,
		Status: status,
	}
}

// WriteTo write negotiation username password reply packet into client
func (r *UserPassNegotiationReply) WriteTo(w io.Writer) (n int64, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.UserPassNegotiationReply.WriteTo()")
	}()

	i, err := w.Write([]byte{r.Ver, r.Status})
	if err != nil {
		return 0, errors.Wrap(err, "failed to write username/password negotiation reply")
	}

	slog.Debug("Sent username/password negotiation reply",
		slog.Any("version", r.Ver),
		slog.Any("status", r.Status))

	return int64(i), nil
}

// NewRequestFrom read requst packet from client
func NewRequestFrom(r io.Reader) (req *Request, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.NewRequestFrom()")
	}()

	bb := make([]byte, 4)
	if _, err := io.ReadFull(r, bb); err != nil {
		return nil, errors.Wrap(err, "failed to read request header")
	}
	if bb[0] != Ver {
		return nil, ErrVersion
	}
	var addr []byte
	if bb[3] == ATYPIPv4 {
		addr = make([]byte, 4)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, errors.Wrap(err, "failed to read IPv4 address")
		}
	} else if bb[3] == ATYPIPv6 {
		addr = make([]byte, 16)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, errors.Wrap(err, "failed to read IPv6 address")
		}
	} else if bb[3] == ATYPDomain {
		dal := make([]byte, 1)
		if _, err := io.ReadFull(r, dal); err != nil {
			return nil, errors.Wrap(err, "failed to read domain length")
		}
		if dal[0] == 0 {
			return nil, ErrBadRequest
		}
		addr = make([]byte, int(dal[0]))
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, errors.Wrap(err, "failed to read domain")
		}
		addr = append(dal, addr...)
	} else {
		return nil, ErrBadRequest
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(r, port); err != nil {
		return nil, errors.Wrap(err, "failed to read port")
	}

	req = &Request{
		Ver:     bb[0],
		Cmd:     bb[1],
		Rsv:     bb[2],
		Atyp:    bb[3],
		DstAddr: addr,
		DstPort: port,
	}

	slog.Debug("Got request",
		slog.Any("version", bb[0]),
		slog.Any("cmd", bb[1]),
		slog.Any("rsv", bb[2]),
		slog.Any("atyp", bb[3]),
		slog.Any("dst_addr", addr),
		slog.Any("dst_port", port))

	return req, nil
}

// NewReply return reply packet can be writed into client, bndaddr should not have domain length
func NewReply(rep byte, atyp byte, bndaddr []byte, bndport []byte) *Reply {
	if atyp == ATYPDomain {
		bndaddr = append([]byte{byte(len(bndaddr))}, bndaddr...)
	}
	return &Reply{
		Ver:     Ver,
		Rep:     rep,
		Rsv:     0x00,
		Atyp:    atyp,
		BndAddr: bndaddr,
		BndPort: bndport,
	}
}

// WriteTo write reply packet into client
func (r *Reply) WriteTo(w io.Writer) (n int64, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.Reply.WriteTo()")
	}()

	i, err := w.Write(append(append([]byte{r.Ver, r.Rep, r.Rsv, r.Atyp}, r.BndAddr...), r.BndPort...))
	if err != nil {
		return 0, errors.Wrap(err, "failed to write reply")
	}

	slog.Debug("Sent reply",
		slog.Any("version", r.Ver),
		slog.Any("reply", r.Rep),
		slog.Any("rsv", r.Rsv),
		slog.Any("atyp", r.Atyp),
		slog.Any("bnd_addr", r.BndAddr),
		slog.Any("bnd_port", r.BndPort))

	return int64(i), nil
}

func NewDatagramFromBytes(bb []byte) (dg *Datagram, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.NewDatagramFromBytes()")
	}()

	n := len(bb)
	minl := 4
	if n < minl {
		return nil, ErrBadRequest
	}
	var addr []byte
	if bb[3] == ATYPIPv4 {
		minl += 4
		if n < minl {
			return nil, ErrBadRequest
		}
		addr = bb[minl-4 : minl]
	} else if bb[3] == ATYPIPv6 {
		minl += 16
		if n < minl {
			return nil, ErrBadRequest
		}
		addr = bb[minl-16 : minl]
	} else if bb[3] == ATYPDomain {
		minl += 1
		if n < minl {
			return nil, ErrBadRequest
		}
		l := bb[4]
		if l == 0 {
			return nil, ErrBadRequest
		}
		minl += int(l)
		if n < minl {
			return nil, ErrBadRequest
		}
		addr = bb[minl-int(l) : minl]
		addr = append([]byte{l}, addr...)
	} else {
		return nil, ErrBadRequest
	}
	minl += 2
	if n <= minl {
		return nil, ErrBadRequest
	}
	port := bb[minl-2 : minl]
	data := bb[minl:]
	d := &Datagram{
		Rsv:     bb[0:2],
		Frag:    bb[2],
		Atyp:    bb[3],
		DstAddr: addr,
		DstPort: port,
		Data:    data,
	}

	slog.Debug("Got datagram",
		slog.Any("rsv", d.Rsv),
		slog.Any("frag", d.Frag),
		slog.Any("atyp", d.Atyp),
		slog.Any("dst_addr", d.DstAddr),
		slog.Any("dst_port", d.DstPort),
		slog.Int("data_length", len(d.Data)),
		slog.String("address", d.Address()))

	return d, nil
}

// NewDatagram return datagram packet can be writed into client, dstaddr should not have domain length
func NewDatagram(atyp byte, dstaddr []byte, dstport []byte, data []byte) *Datagram {
	if atyp == ATYPDomain {
		dstaddr = append([]byte{byte(len(dstaddr))}, dstaddr...)
	}
	return &Datagram{
		Rsv:     []byte{0x00, 0x00},
		Frag:    0x00,
		Atyp:    atyp,
		DstAddr: dstaddr,
		DstPort: dstport,
		Data:    data,
	}
}

// Bytes return []byte
func (d *Datagram) Bytes() []byte {
	b := make([]byte, 0)
	b = append(b, d.Rsv...)
	b = append(b, d.Frag)
	b = append(b, d.Atyp)
	b = append(b, d.DstAddr...)
	b = append(b, d.DstPort...)
	b = append(b, d.Data...)
	return b
}
