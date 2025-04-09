package socks5

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/VanO219/errors"
	cache "github.com/patrickmn/go-cache"
	"github.com/txthinking/runnergroup"
)

var (
	// ErrUnsupportCmd is the error when got unsupport command
	ErrUnsupportCmd = errors.New("Unsupport Command")
	// ErrUserPassAuth is the error when got invalid username or password
	ErrUserPassAuth = errors.New("Invalid Username or Password for Auth")
)

// Server is socks5 server wrapper
type Server struct {
	UserName          string
	Password          string
	Method            byte
	SupportedCommands []byte
	Addr              string
	ServerAddr        net.Addr
	UDPConn           *net.UDPConn
	UDPExchanges      *cache.Cache
	TCPTimeout        int
	UDPTimeout        int
	Handle            Handler
	AssociatedUDP     *cache.Cache
	UDPSrc            *cache.Cache
	RunnerGroup       *runnergroup.RunnerGroup
	// RFC: [UDP ASSOCIATE] The server MAY use this information to limit access to the association. Default false, no limit.
	LimitUDP bool
}

// UDPExchange used to store client address and remote connection
type UDPExchange struct {
	ClientAddr *net.UDPAddr
	RemoteConn net.Conn
}

// NewClassicServer return a server which allow none method
func NewClassicServer(addr, ip, username, password string, tcpTimeout, udpTimeout int) (s *Server, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.NewClassicServer()")
	}()

	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errors.Wrap(err, "failed to split host:port")
	}

	saddr, err := Resolve("udp", net.JoinHostPort(ip, p))
	if err != nil {
		return nil, errors.Wrap(err, "failed to resolve address")
	}

	m := MethodNone
	if username != "" && password != "" {
		m = MethodUsernamePassword
	}

	cs := cache.New(cache.NoExpiration, cache.NoExpiration)
	cs1 := cache.New(cache.NoExpiration, cache.NoExpiration)
	cs2 := cache.New(cache.NoExpiration, cache.NoExpiration)

	s = &Server{
		Method:            m,
		UserName:          username,
		Password:          password,
		SupportedCommands: []byte{CmdConnect, CmdUDP},
		Addr:              addr,
		ServerAddr:        saddr,
		UDPExchanges:      cs,
		TCPTimeout:        tcpTimeout,
		UDPTimeout:        udpTimeout,
		AssociatedUDP:     cs1,
		UDPSrc:            cs2,
		RunnerGroup:       runnergroup.New(),
	}
	return s, nil
}

// Negotiate handle negotiate packet.
// This method do not handle gssapi(0x01) method now.
// Error or OK both replied.
func (s *Server) Negotiate(rw io.ReadWriter) (err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.Server.Negotiate()")
	}()

	rq, err := NewNegotiationRequestFrom(rw)
	if err != nil {
		return errors.Wrap(err, "failed to read negotiation request")
	}

	var got bool
	var m byte
	for _, m = range rq.Methods {
		if m == s.Method {
			got = true
		}
	}
	if !got {
		rp := NewNegotiationReply(MethodUnsupportAll)
		if _, err := rp.WriteTo(rw); err != nil {
			return errors.Wrap(err, "failed to write negotiation reply")
		}
	}

	rp := NewNegotiationReply(s.Method)
	if _, err := rp.WriteTo(rw); err != nil {
		return errors.Wrap(err, "failed to write negotiation reply")
	}

	if s.Method == MethodUsernamePassword {
		urq, err := NewUserPassNegotiationRequestFrom(rw)
		if err != nil {
			return errors.Wrap(err, "failed to read username/password request")
		}
		if string(urq.Uname) != s.UserName || string(urq.Passwd) != s.Password {
			urp := NewUserPassNegotiationReply(UserPassStatusFailure)
			if _, err := urp.WriteTo(rw); err != nil {
				return errors.Wrap(err, "failed to write username/password reply")
			}
			return ErrUserPassAuth
		}
		urp := NewUserPassNegotiationReply(UserPassStatusSuccess)
		if _, err := urp.WriteTo(rw); err != nil {
			return errors.Wrap(err, "failed to write username/password reply")
		}
	}
	return nil
}

// GetRequest get request packet from client, and check command according to SupportedCommands
// Error replied.
func (s *Server) GetRequest(rw io.ReadWriter) (r *Request, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.Server.GetRequest()")
	}()

	r, err = NewRequestFrom(rw)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read request")
	}

	var supported bool
	for _, c := range s.SupportedCommands {
		if r.Cmd == c {
			supported = true
			break
		}
	}
	if !supported {
		var p *Reply
		if r.Atyp == ATYPIPv4 || r.Atyp == ATYPDomain {
			p = NewReply(RepCommandNotSupported, ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = NewReply(RepCommandNotSupported, ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err := p.WriteTo(rw); err != nil {
			return nil, errors.Wrap(err, "failed to write reply")
		}
		return nil, ErrUnsupportCmd
	}
	return r, nil
}

// Run server
func (s *Server) ListenAndServe(h Handler) (err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.Server.ListenAndServe()")
	}()

	// Создаем фоновый контекст для запуска сервера
	return s.ListenAndServeWithContext(context.Background(), h)
}

// ListenAndServeWithContext runs server with context control
func (s *Server) ListenAndServeWithContext(ctx context.Context, h Handler) (err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.Server.ListenAndServeWithContext()")
	}()

	if h == nil {
		s.Handle = &DefaultHandle{}
	} else {
		s.Handle = h
	}

	// Создаем контекст с отменой, привязанный к переданному контексту
	serverCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Горутина для мониторинга контекста
	go func() {
		<-ctx.Done()
		slog.Info("Server context canceled, initiating shutdown")
		s.Shutdown()
	}()

	addr, err := net.ResolveTCPAddr("tcp", s.Addr)
	if err != nil {
		return errors.Wrap(err, "failed to resolve TCP address")
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return errors.Wrap(err, "failed to listen on TCP address")
	}

	s.RunnerGroup.Add(&runnergroup.Runner{
		Start: func() error {
			for {
				// Проверяем отмену контекста
				select {
				case <-serverCtx.Done():
					return serverCtx.Err()
				default:
					// Устанавливаем таймаут на принятие соединения для периодической проверки контекста
					l.SetDeadline(time.Now().Add(time.Second * 3))
					c, err := l.AcceptTCP()
					if err != nil {
						// Ошибка таймаута, проверяем контекст и продолжаем
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							continue
						}
						return err
					}
					// Для каждого соединения создаем свой контекст
					connCtx, connCancel := context.WithCancel(serverCtx)
					go func(ctx context.Context, cancel context.CancelFunc, c *net.TCPConn) {
						defer func() {
							c.Close()
							cancel()
						}()
						if err := s.Negotiate(c); err != nil {
							slog.Error("Failed to negotiate", slog.Any("error", err))
							return
						}
						r, err := s.GetRequest(c)
						if err != nil {
							slog.Error("Failed to get request", slog.Any("error", err))
							return
						}
						if err := s.Handle.TCPHandle(ctx, s, c, r); err != nil {
							slog.Error("Failed to handle TCP", slog.Any("error", err))
						}
					}(connCtx, connCancel, c)
				}
			}
		},
		Stop: func() error {
			cancel() // Отменяем серверный контекст при остановке
			return l.Close()
		},
	})

	addr1, err := net.ResolveUDPAddr("udp", s.Addr)
	if err != nil {
		l.Close()
		return errors.Wrap(err, "failed to resolve UDP address")
	}

	s.UDPConn, err = net.ListenUDP("udp", addr1)
	if err != nil {
		l.Close()
		return errors.Wrap(err, "failed to listen on UDP address")
	}

	s.RunnerGroup.Add(&runnergroup.Runner{
		Start: func() error {
			for {
				// Проверяем отмену контекста
				select {
				case <-serverCtx.Done():
					return serverCtx.Err()
				default:
					// Устанавливаем таймаут для чтения UDP, чтобы периодически проверять контекст
					s.UDPConn.SetReadDeadline(time.Now().Add(time.Second * 3))
					b := make([]byte, 65507)
					n, addr, err := s.UDPConn.ReadFromUDP(b)
					if err != nil {
						// Ошибка таймаута, проверяем контекст и продолжаем
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							continue
						}
						return err
					}
					// Создаем контекст для обработки датаграммы
					dgCtx, dgCancel := context.WithCancel(serverCtx)
					go func(ctx context.Context, cancel context.CancelFunc, addr *net.UDPAddr, b []byte) {
						defer cancel()
						d, err := NewDatagramFromBytes(b)
						if err != nil {
							slog.Error("Failed to parse datagram", slog.Any("error", err))
							return
						}
						if d.Frag != 0x00 {
							slog.Info("Ignoring fragmented datagram", slog.Any("frag", d.Frag))
							return
						}
						if err := s.Handle.UDPHandle(ctx, s, addr, d); err != nil {
							slog.Error("Failed to handle UDP", slog.Any("error", err))
							return
						}
					}(dgCtx, dgCancel, addr, b[0:n])
				}
			}
		},
		Stop: func() error {
			cancel() // Отменяем серверный контекст при остановке
			return s.UDPConn.Close()
		},
	})

	return s.RunnerGroup.Wait()
}

// Stop server
func (s *Server) Shutdown() error {
	return s.RunnerGroup.Done()
}

// Handler handle tcp, udp request
type Handler interface {
	// Request has not been replied yet
	TCPHandle(context.Context, *Server, *net.TCPConn, *Request) error
	UDPHandle(context.Context, *Server, *net.UDPAddr, *Datagram) error
}

// DefaultHandle implements Handler interface
type DefaultHandle struct {
}

// TCPHandle auto handle request. You may prefer to do yourself.
func (h *DefaultHandle) TCPHandle(ctx context.Context, s *Server, c *net.TCPConn, r *Request) (err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.DefaultHandle.TCPHandle()")
	}()

	if r.Cmd == CmdConnect {
		rc, err := r.Connect(c)
		if err != nil {
			return errors.Wrap(err, "failed to connect")
		}
		defer rc.Close()

		// Создаем контекст с возможностью отмены
		connCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		// Канал для сигнализации о завершении горутины
		doneCh := make(chan struct{})

		// Горутина для чтения из удаленного соединения и записи в клиентское
		go func() {
			defer func() {
				close(doneCh)
				cancel() // Отменяем контекст при завершении горутины
			}()

			var bf [1024 * 2]byte
			for {
				select {
				case <-connCtx.Done():
					return
				default:
					if s.TCPTimeout != 0 {
						if err := rc.SetDeadline(time.Now().Add(time.Duration(s.TCPTimeout) * time.Second)); err != nil {
							slog.Error("Failed to set deadline", slog.Any("error", err))
							return
						}
					}
					i, err := rc.Read(bf[:])
					if err != nil {
						return
					}
					if _, err := c.Write(bf[0:i]); err != nil {
						return
					}
				}
			}
		}()

		// Чтение из клиентского соединения и запись в удаленное
		var bf [1024 * 2]byte
		for {
			select {
			case <-ctx.Done():
				// Контекст был отменен, завершаем работу
				return ctx.Err()
			case <-doneCh:
				// Горутина чтения завершилась
				return nil
			default:
				if s.TCPTimeout != 0 {
					if err := c.SetDeadline(time.Now().Add(time.Duration(s.TCPTimeout) * time.Second)); err != nil {
						return errors.Wrap(err, "failed to set client deadline")
					}
				}
				i, err := c.Read(bf[:])
				if err != nil {
					return nil
				}
				if _, err := rc.Write(bf[0:i]); err != nil {
					return nil
				}
			}
		}
	}

	if r.Cmd == CmdUDP {
		caddr, err := r.UDP(c, s.ServerAddr)
		if err != nil {
			return errors.Wrap(err, "failed to setup UDP")
		}

		ch := make(chan byte)
		defer close(ch)
		s.AssociatedUDP.Set(caddr.String(), ch, -1)
		defer s.AssociatedUDP.Delete(caddr.String())

		// Создаем контекст с отменой
		udpCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		// Отдельная горутина для мониторинга контекста и закрытия соединения
		go func() {
			select {
			case <-udpCtx.Done():
				c.Close()
			case <-ch:
				// Канал закрылся, ничего не делаем
			}
		}()

		io.Copy(io.Discard, c)
		slog.Debug("TCP connection associated with UDP closed", slog.String("client_addr", caddr.String()))

		return nil
	}
	return ErrUnsupportCmd
}

// UDPHandle auto handle packet. You may prefer to do yourself.
func (h *DefaultHandle) UDPHandle(ctx context.Context, s *Server, addr *net.UDPAddr, d *Datagram) (err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.DefaultHandle.UDPHandle()")
	}()

	src := addr.String()
	var ch chan byte
	if s.LimitUDP {
		any, ok := s.AssociatedUDP.Get(src)
		if !ok {
			return fmt.Errorf("This udp address %s is not associated with tcp", src)
		}
		ch = any.(chan byte)
	}

	send := func(ue *UDPExchange, data []byte) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch:
			return fmt.Errorf("This udp address %s is not associated with tcp", src)
		default:
			_, err := ue.RemoteConn.Write(data)
			if err != nil {
				return errors.Wrap(err, "failed to write to remote")
			}
			slog.Debug("Sent UDP data to remote",
				slog.String("client", ue.ClientAddr.String()),
				slog.String("server_local", ue.RemoteConn.LocalAddr().String()),
				slog.String("remote", ue.RemoteConn.RemoteAddr().String()),
				slog.Int("data_len", len(data)))
		}
		return nil
	}

	dst := d.Address()
	var ue *UDPExchange
	iue, ok := s.UDPExchanges.Get(src + dst)
	if ok {
		ue = iue.(*UDPExchange)
		return send(ue, d.Data)
	}

	slog.Debug("Creating new UDP connection", slog.String("dst", dst))

	var laddr string
	any, ok := s.UDPSrc.Get(src + dst)
	if ok {
		laddr = any.(string)
	}

	rc, err := DialUDP("udp", laddr, dst)
	if err != nil {
		if !strings.Contains(err.Error(), "address already in use") && !strings.Contains(err.Error(), "can't assign requested address") {
			return errors.Wrap(err, "failed to dial UDP")
		}
		rc, err = DialUDP("udp", "", dst)
		if err != nil {
			return errors.Wrap(err, "failed to dial UDP without local address")
		}
		laddr = ""
	}

	if laddr == "" {
		s.UDPSrc.Set(src+dst, rc.LocalAddr().String(), -1)
	}

	ue = &UDPExchange{
		ClientAddr: addr,
		RemoteConn: rc,
	}

	slog.Debug("Created remote UDP connection",
		slog.String("client", addr.String()),
		slog.String("server_local", ue.RemoteConn.LocalAddr().String()),
		slog.String("remote", d.Address()))

	if err := send(ue, d.Data); err != nil {
		ue.RemoteConn.Close()
		return errors.Wrap(err, "failed to send initial data")
	}

	s.UDPExchanges.Set(src+dst, ue, -1)

	go func(ue *UDPExchange, dst string) {
		defer func() {
			ue.RemoteConn.Close()
			s.UDPExchanges.Delete(ue.ClientAddr.String() + dst)
		}()

		var b [65507]byte
		for {
			select {
			case <-ctx.Done():
				slog.Debug("Context canceled", slog.String("client", ue.ClientAddr.String()))
				return
			case <-ch:
				slog.Debug("TCP connection closed", slog.String("client", ue.ClientAddr.String()))
				return
			default:
				if s.UDPTimeout != 0 {
					if err := ue.RemoteConn.SetDeadline(time.Now().Add(time.Duration(s.UDPTimeout) * time.Second)); err != nil {
						slog.Error("Failed to set deadline", slog.Any("error", err))
						return
					}
				}

				n, err := ue.RemoteConn.Read(b[:])
				if err != nil {
					return
				}

				slog.Debug("Got UDP data from remote",
					slog.String("client", ue.ClientAddr.String()),
					slog.String("server_local", ue.RemoteConn.LocalAddr().String()),
					slog.String("remote", ue.RemoteConn.RemoteAddr().String()),
					slog.Int("data_len", n))

				a, addr, port, err := ParseAddress(dst)
				if err != nil {
					slog.Error("Failed to parse address", slog.Any("error", err))
					return
				}

				if a == ATYPDomain {
					addr = addr[1:]
				}

				d1 := NewDatagram(a, addr, port, b[0:n])
				if _, err := s.UDPConn.WriteToUDP(d1.Bytes(), ue.ClientAddr); err != nil {
					return
				}

				slog.Debug("Sent datagram to client",
					slog.String("client", ue.ClientAddr.String()),
					slog.String("server_local", ue.RemoteConn.LocalAddr().String()),
					slog.String("remote", ue.RemoteConn.RemoteAddr().String()),
					slog.Any("rsv", d1.Rsv),
					slog.Any("frag", d1.Frag),
					slog.Any("atyp", d1.Atyp),
					slog.Any("dst_addr", d1.DstAddr),
					slog.Any("dst_port", d1.DstPort),
					slog.Int("data_len", len(d1.Data)),
					slog.String("address", d1.Address()))
			}
		}
	}(ue, dst)

	return nil
}
