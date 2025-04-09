package socks5

import (
	"io"
	"log/slog"

	"github.com/VanO219/errors"
)

var (
	// ErrBadReply is the error when read reply
	ErrBadReply = errors.New("Bad Reply")
)

// NewNegotiationRequest return negotiation request packet can be writed into server
func NewNegotiationRequest(methods []byte) *NegotiationRequest {
	return &NegotiationRequest{
		Ver:      Ver,
		NMethods: byte(len(methods)),
		Methods:  methods,
	}
}

// WriteTo write negotiation request packet into server
func (r *NegotiationRequest) WriteTo(w io.Writer) (n int64, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.NegotiationRequest.WriteTo()")
	}()

	i, err := WriteAll(w, append([]byte{r.Ver, r.NMethods}, r.Methods...))
	if err != nil {
		return 0, errors.Wrap(err, "failed to write negotiation request")
	}

	slog.Debug("Sent negotiation request",
		slog.Any("version", r.Ver),
		slog.Any("methods_count", r.NMethods),
		slog.Any("methods", r.Methods))

	return int64(i), nil
}

// NewNegotiationReplyFrom read negotiation reply packet from server
func NewNegotiationReplyFrom(r io.Reader) (reply *NegotiationReply, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.NewNegotiationReplyFrom()")
	}()

	bb := make([]byte, 2)
	if _, err := io.ReadFull(r, bb); err != nil {
		return nil, errors.Wrap(err, "failed to read negotiation reply")
	}
	if bb[0] != Ver {
		return nil, ErrVersion
	}

	slog.Debug("Got negotiation reply",
		slog.Any("version", bb[0]),
		slog.Any("method", bb[1]))

	return &NegotiationReply{
		Ver:    bb[0],
		Method: bb[1],
	}, nil
}

// NewUserPassNegotiationRequest return user password negotiation request packet can be writed into server
func NewUserPassNegotiationRequest(username []byte, password []byte) *UserPassNegotiationRequest {
	return &UserPassNegotiationRequest{
		Ver:    UserPassVer,
		Ulen:   byte(len(username)),
		Uname:  username,
		Plen:   byte(len(password)),
		Passwd: password,
	}
}

// WriteTo write user password negotiation request packet into server
func (r *UserPassNegotiationRequest) WriteTo(w io.Writer) (n int64, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.UserPassNegotiationRequest.WriteTo()")
	}()

	i, err := WriteAll(w, append(append(append([]byte{r.Ver, r.Ulen}, r.Uname...), r.Plen), r.Passwd...))
	if err != nil {
		return 0, errors.Wrap(err, "failed to write username/password negotiation request")
	}

	slog.Debug("Sent username/password negotiation request",
		slog.Any("version", r.Ver),
		slog.Any("username_length", r.Ulen),
		slog.String("username", string(r.Uname)),
		slog.Any("password_length", r.Plen),
		slog.String("password", "[MASKED]"))

	return int64(i), nil
}

// NewUserPassNegotiationReplyFrom read user password negotiation reply packet from server
func NewUserPassNegotiationReplyFrom(r io.Reader) (reply *UserPassNegotiationReply, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.NewUserPassNegotiationReplyFrom()")
	}()

	bb := make([]byte, 2)
	if _, err := io.ReadFull(r, bb); err != nil {
		return nil, errors.Wrap(err, "failed to read username/password negotiation reply")
	}
	if bb[0] != UserPassVer {
		return nil, ErrUserPassVersion
	}

	slog.Debug("Got username/password negotiation reply",
		slog.Any("version", bb[0]),
		slog.Any("status", bb[1]))

	return &UserPassNegotiationReply{
		Ver:    bb[0],
		Status: bb[1],
	}, nil
}

// NewRequest return request packet can be writed into server, dstaddr should not have domain length
func NewRequest(cmd byte, atyp byte, dstaddr []byte, dstport []byte) *Request {
	if atyp == ATYPDomain {
		dstaddr = append([]byte{byte(len(dstaddr))}, dstaddr...)
	}
	return &Request{
		Ver:     Ver,
		Cmd:     cmd,
		Rsv:     0x00,
		Atyp:    atyp,
		DstAddr: dstaddr,
		DstPort: dstport,
	}
}

// WriteTo write request packet into server
func (r *Request) WriteTo(w io.Writer) (n int64, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.Request.WriteTo()")
	}()

	i, err := WriteAll(w, append(append([]byte{r.Ver, r.Cmd, r.Rsv, r.Atyp}, r.DstAddr...), r.DstPort...))
	if err != nil {
		return 0, errors.Wrap(err, "failed to write request")
	}

	slog.Debug("Sent request",
		slog.Any("version", r.Ver),
		slog.Any("cmd", r.Cmd),
		slog.Any("rsv", r.Rsv),
		slog.Any("atyp", r.Atyp),
		slog.Any("dst_addr", r.DstAddr),
		slog.Any("dst_port", r.DstPort))

	return int64(i), nil
}

// NewReplyFrom read reply packet from server
func NewReplyFrom(r io.Reader) (reply *Reply, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.NewReplyFrom()")
	}()

	bb := make([]byte, 4)
	if _, err := io.ReadFull(r, bb); err != nil {
		return nil, errors.Wrap(err, "failed to read reply header")
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
			return nil, ErrBadReply
		}
		addr = make([]byte, int(dal[0]))
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, errors.Wrap(err, "failed to read domain address")
		}
		addr = append(dal, addr...)
	} else {
		return nil, ErrBadReply
	}

	port := make([]byte, 2)
	if _, err := io.ReadFull(r, port); err != nil {
		return nil, errors.Wrap(err, "failed to read port")
	}

	reply = &Reply{
		Ver:     bb[0],
		Rep:     bb[1],
		Rsv:     bb[2],
		Atyp:    bb[3],
		BndAddr: addr,
		BndPort: port,
	}

	slog.Debug("Got reply",
		slog.Any("version", bb[0]),
		slog.Any("reply", bb[1]),
		slog.Any("rsv", bb[2]),
		slog.Any("atyp", bb[3]),
		slog.Any("bnd_addr", addr),
		slog.Any("bnd_port", port))

	return reply, nil
}
