package socks5

import (
	"net"
	"time"

	"github.com/VanO219/errors"
)

// Client is socks5 client wrapper
type Client struct {
	Server   string
	UserName string
	Password string
	// On cmd UDP, let server control the tcp and udp connection relationship
	TCPConn       net.Conn
	UDPConn       net.Conn
	RemoteAddress net.Addr
	TCPTimeout    int
	UDPTimeout    int
	Dst           string
}

// NewClient creates a new SOCKS5 client with the provided parameters
func NewClient(addr, username, password string, tcpTimeout, udpTimeout int) (c *Client, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.NewClient()")
	}()

	c = &Client{
		Server:     addr,
		UserName:   username,
		Password:   password,
		TCPTimeout: tcpTimeout,
		UDPTimeout: udpTimeout,
	}
	return c, nil
}

func (c *Client) Dial(network, addr string) (conn net.Conn, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.Client.Dial()")
	}()
	return c.DialWithLocalAddr(network, "", addr, nil)
}

// If you want to send address that expects to use to send UDP, just assign it to src, otherwise it will send zero address.
// Recommend specifying the src address in a non-NAT environment, and leave it blank in other cases.
func (c *Client) DialWithLocalAddr(network, src, dst string, remoteAddr net.Addr) (conn net.Conn, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.Client.DialWithLocalAddr()")
	}()

	c = &Client{
		Server:        c.Server,
		UserName:      c.UserName,
		Password:      c.Password,
		TCPTimeout:    c.TCPTimeout,
		UDPTimeout:    c.UDPTimeout,
		Dst:           dst,
		RemoteAddress: remoteAddr,
	}

	if network == "tcp" {
		var laddr net.Addr
		if src != "" {
			laddr, err = net.ResolveTCPAddr("tcp", src)
			if err != nil {
				return nil, errors.Wrap(err, "failed to resolve TCP address")
			}
		}
		if err := c.Negotiate(laddr); err != nil {
			return nil, errors.Wrap(err, "failed to negotiate")
		}
		a, h, p, err := ParseAddress(dst)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse address")
		}
		if a == ATYPDomain {
			h = h[1:]
		}
		if _, err := c.Request(NewRequest(CmdConnect, a, h, p)); err != nil {
			return nil, errors.Wrap(err, "failed to send connect request")
		}
		return c, nil
	}

	if network == "udp" {
		var laddr net.Addr
		if src != "" {
			laddr, err = net.ResolveTCPAddr("tcp", src)
			if err != nil {
				return nil, errors.Wrap(err, "failed to resolve TCP address")
			}
		}
		if err := c.Negotiate(laddr); err != nil {
			return nil, errors.Wrap(err, "failed to negotiate")
		}

		a, h, p := ATYPIPv4, net.IPv4zero, []byte{0x00, 0x00}
		if src != "" {
			a, h, p, err = ParseAddress(src)
			if err != nil {
				return nil, errors.Wrap(err, "failed to parse source address")
			}
			if a == ATYPDomain {
				h = h[1:]
			}
		}
		rp, err := c.Request(NewRequest(CmdUDP, a, h, p))
		if err != nil {
			return nil, errors.Wrap(err, "failed to send UDP request")
		}

		c.UDPConn, err = DialUDP("udp", src, rp.Address())
		if err != nil {
			return nil, errors.Wrap(err, "failed to dial UDP")
		}

		if c.UDPTimeout != 0 {
			if err := c.UDPConn.SetDeadline(time.Now().Add(time.Duration(c.UDPTimeout) * time.Second)); err != nil {
				return nil, errors.Wrap(err, "failed to set UDP deadline")
			}
		}
		return c, nil
	}

	return nil, errors.New("unsupported network type")
}

func (c *Client) Read(b []byte) (n int, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.Client.Read()")
	}()

	if c.UDPConn == nil {
		return c.TCPConn.Read(b)
	}

	n, err = c.UDPConn.Read(b)
	if err != nil {
		return 0, errors.Wrap(err, "failed to read from UDP connection")
	}

	d, err := NewDatagramFromBytes(b[0:n])
	if err != nil {
		return 0, errors.Wrap(err, "failed to parse datagram")
	}

	n = copy(b, d.Data)
	return n, nil
}

func (c *Client) Write(b []byte) (n int, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.Client.Write()")
	}()

	if c.UDPConn == nil {
		return c.TCPConn.Write(b)
	}

	a, h, p, err := ParseAddress(c.Dst)
	if err != nil {
		return 0, errors.Wrap(err, "failed to parse destination address")
	}

	if a == ATYPDomain {
		h = h[1:]
	}

	d := NewDatagram(a, h, p, b)
	b1 := d.Bytes()
	n, err = c.UDPConn.Write(b1)
	if err != nil {
		return 0, errors.Wrap(err, "failed to write to UDP connection")
	}

	if len(b1) != n {
		return 0, errors.New("not all data was written")
	}

	return len(b), nil
}

func (c *Client) Close() (err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.Client.Close()")
	}()

	if c.UDPConn == nil {
		return c.TCPConn.Close()
	}

	if c.TCPConn != nil {
		if err := c.TCPConn.Close(); err != nil {
			return errors.Wrap(err, "failed to close TCP connection")
		}
	}

	return c.UDPConn.Close()
}

func (c *Client) LocalAddr() net.Addr {
	if c.UDPConn == nil {
		return c.TCPConn.LocalAddr()
	}
	return c.UDPConn.LocalAddr()
}

func (c *Client) RemoteAddr() net.Addr {
	return c.RemoteAddress
}

func (c *Client) SetDeadline(t time.Time) (err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.Client.SetDeadline()")
	}()

	if c.UDPConn == nil {
		return c.TCPConn.SetDeadline(t)
	}
	return c.UDPConn.SetDeadline(t)
}

func (c *Client) SetReadDeadline(t time.Time) (err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.Client.SetReadDeadline()")
	}()

	if c.UDPConn == nil {
		return c.TCPConn.SetReadDeadline(t)
	}
	return c.UDPConn.SetReadDeadline(t)
}

func (c *Client) SetWriteDeadline(t time.Time) (err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.Client.SetWriteDeadline()")
	}()

	if c.UDPConn == nil {
		return c.TCPConn.SetWriteDeadline(t)
	}
	return c.UDPConn.SetWriteDeadline(t)
}

func (c *Client) Negotiate(laddr net.Addr) (err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.Client.Negotiate()")
	}()

	src := ""
	if laddr != nil {
		src = laddr.String()
	}

	c.TCPConn, err = DialTCP("tcp", src, c.Server)
	if err != nil {
		return errors.Wrap(err, "failed to dial TCP")
	}

	if c.TCPTimeout != 0 {
		if err := c.TCPConn.SetDeadline(time.Now().Add(time.Duration(c.TCPTimeout) * time.Second)); err != nil {
			return errors.Wrap(err, "failed to set TCP deadline")
		}
	}

	m := MethodNone
	if c.UserName != "" && c.Password != "" {
		m = MethodUsernamePassword
	}

	rq := NewNegotiationRequest([]byte{m})
	if _, err := rq.WriteTo(c.TCPConn); err != nil {
		return errors.Wrap(err, "failed to write negotiation request")
	}

	rp, err := NewNegotiationReplyFrom(c.TCPConn)
	if err != nil {
		return errors.Wrap(err, "failed to read negotiation reply")
	}

	if rp.Method != m {
		return errors.New("unsupported authentication method")
	}

	if m == MethodUsernamePassword {
		urq := NewUserPassNegotiationRequest([]byte(c.UserName), []byte(c.Password))
		if _, err := urq.WriteTo(c.TCPConn); err != nil {
			return errors.Wrap(err, "failed to write username/password negotiation request")
		}

		urp, err := NewUserPassNegotiationReplyFrom(c.TCPConn)
		if err != nil {
			return errors.Wrap(err, "failed to read username/password negotiation reply")
		}

		if urp.Status != UserPassStatusSuccess {
			return ErrUserPassAuth
		}
	}

	return nil
}

func (c *Client) Request(r *Request) (rp *Reply, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.Client.Request()")
	}()

	if _, err := r.WriteTo(c.TCPConn); err != nil {
		return nil, errors.Wrap(err, "failed to write request")
	}

	rp, err = NewReplyFrom(c.TCPConn)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read reply")
	}

	if rp.Rep != RepSuccess {
		return nil, errors.New("host unreachable")
	}

	return rp, nil
}
