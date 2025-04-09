package socks5

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync"
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

// BufferPool представляет пул буферов для снижения нагрузки на GC
type BufferPool struct {
	pool sync.Pool
}

// NewBufferPool создает новый пул буферов указанного размера
func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() any {
				return make([]byte, size)
			},
		},
	}
}

// Get возвращает буфер из пула
func (p *BufferPool) Get() []byte {
	return p.pool.Get().([]byte)
}

// Put возвращает буфер в пул после обнуления его содержимого
func (p *BufferPool) Put(b []byte) {
	// Обнуляем буфер для предотвращения повторного использования старых данных
	for i := range b {
		b[i] = 0
	}
	p.pool.Put(b)
}

// Clear очищает пул буферов
// Примечание: sync.Pool автоматически очищается GC,
// но мы можем форсировать это, заменяя сам пул
func (p *BufferPool) Clear() {
	// Создаем новый пул с тем же размером буфера
	size := len(p.Get())
	p.Put(make([]byte, size)) // Возвращаем буфер обратно

	// Заменяем текущий пул новым
	p.pool = sync.Pool{
		New: func() any {
			return make([]byte, size)
		},
	}

	slog.Debug("Buffer pool cleared", slog.Int("buffer_size", size))
}

// UDPConnectionPool представляет пул UDP соединений для снижения нагрузки на сеть
type UDPConnectionPool struct {
	sync.Mutex
	pool        map[string][]*net.UDPConn // ключ - назначение, значение - доступные соединения
	maxIdle     int                       // максимальное количество простаивающих соединений в пуле
	maxLifetime time.Duration             // максимальное время жизни соединения
}

// NewUDPConnectionPool создает новый пул UDP соединений
func NewUDPConnectionPool(maxIdle int, maxLifetime time.Duration) *UDPConnectionPool {
	p := &UDPConnectionPool{
		pool:        make(map[string][]*net.UDPConn),
		maxIdle:     maxIdle,
		maxLifetime: maxLifetime,
	}

	// Запускаем горутину для очистки пула по таймеру
	go p.cleanupRoutine()

	return p
}

// cleanupRoutine периодически очищает старые соединения из пула
func (p *UDPConnectionPool) cleanupRoutine() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		p.cleanup()
	}
}

// cleanup очищает старые соединения из пула
func (p *UDPConnectionPool) cleanup() {
	p.Lock()
	defer p.Unlock()

	// Удаляем лишние соединения из каждого пула
	for dst, conns := range p.pool {
		if len(conns) > p.maxIdle {
			slog.Debug("Cleaning up excess UDP connections",
				slog.String("destination", dst),
				slog.Int("current_count", len(conns)),
				slog.Int("max_idle", p.maxIdle))

			// Закрываем лишние соединения
			for i := p.maxIdle; i < len(conns); i++ {
				conns[i].Close()
			}
			// Обновляем пул
			p.pool[dst] = conns[:p.maxIdle]
		}
	}
}

// Get получает соединение из пула или создает новое
func (p *UDPConnectionPool) Get(srcAddr, dstAddr string) (*net.UDPConn, error) {
	key := srcAddr + ":" + dstAddr

	p.Lock()
	defer p.Unlock()

	// Проверяем, есть ли доступные соединения
	conns, ok := p.pool[key]
	if ok && len(conns) > 0 {
		// Берем последнее соединение из пула
		conn := conns[len(conns)-1]
		// Обновляем пул
		p.pool[key] = conns[:len(conns)-1]
		return conn, nil
	}

	// Нет доступных соединений, создаем новое
	netConn, err := DialUDP(srcAddr, dstAddr)
	if err != nil {
		return nil, err
	}

	// Приводим net.Conn к *net.UDPConn
	conn, ok := netConn.(*net.UDPConn)
	if !ok {
		netConn.Close()
		return nil, errors.New("failed to convert net.Conn to *net.UDPConn")
	}

	return conn, nil
}

// Put возвращает соединение в пул
func (p *UDPConnectionPool) Put(srcAddr, dstAddr string, conn *net.UDPConn) {
	if conn == nil {
		return
	}

	key := srcAddr + ":" + dstAddr

	p.Lock()
	defer p.Unlock()

	// Проверяем, не превышен ли предел
	conns, ok := p.pool[key]
	if !ok {
		conns = make([]*net.UDPConn, 0)
	}

	if len(conns) >= p.maxIdle {
		// Пул переполнен, закрываем соединение
		conn.Close()
		return
	}

	// Добавляем соединение в пул
	p.pool[key] = append(conns, conn)
}

// Добавляем новый метод для освобождения всех ресурсов пула
// Close закрывает все соединения в пуле и очищает его
func (p *UDPConnectionPool) Close() {
	p.Lock()
	defer p.Unlock()

	slog.Info("Closing all UDP connections in pool")

	// Закрываем все соединения во всех пулах
	for dst, conns := range p.pool {
		for _, conn := range conns {
			if err := conn.Close(); err != nil {
				slog.Error("Error closing UDP connection",
					slog.String("destination", dst),
					slog.Any("error", err))
			}
		}
	}

	// Очищаем пул
	p.pool = make(map[string][]*net.UDPConn)
}

// TCPWorkerPool представляет пул воркеров для обработки TCP соединений
type TCPWorkerPool struct {
	workQueue   chan tcpWork
	workerCount int
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
}

// tcpWork представляет задачу для обработки TCP соединения
type tcpWork struct {
	ctx    context.Context
	server *Server
	conn   *net.TCPConn
	req    *Request
}

// NewTCPWorkerPool создает новый пул воркеров для обработки TCP соединений
func NewTCPWorkerPool(ctx context.Context, workerCount int, queueSize int) *TCPWorkerPool {
	workerCtx, cancel := context.WithCancel(ctx)

	pool := &TCPWorkerPool{
		workQueue:   make(chan tcpWork, queueSize),
		workerCount: workerCount,
		ctx:         workerCtx,
		cancel:      cancel,
	}

	return pool
}

// Start запускает пул воркеров
func (p *TCPWorkerPool) Start(handler Handler) {
	for i := 0; i < p.workerCount; i++ {
		p.wg.Add(1)
		go p.worker(i, handler)
	}
}

// worker представляет горутину для обработки TCP соединений
func (p *TCPWorkerPool) worker(id int, handler Handler) {
	defer p.wg.Done()

	slog.Debug("Starting TCP worker", slog.Int("worker_id", id))

	for {
		select {
		case <-p.ctx.Done():
			slog.Debug("TCP worker exiting due to context cancellation", slog.Int("worker_id", id))
			return

		case work, ok := <-p.workQueue:
			if !ok {
				slog.Debug("TCP worker exiting, queue closed", slog.Int("worker_id", id))
				return
			}

			// Обрабатываем TCP соединение
			err := handler.TCPHandle(work.ctx, work.server, work.conn, work.req)
			if err != nil {
				slog.Error("Failed to handle TCP connection",
					slog.Int("worker_id", id),
					slog.Any("error", err))
			}
		}
	}
}

// Submit добавляет задачу в очередь обработки
func (p *TCPWorkerPool) Submit(ctx context.Context, server *Server, conn *net.TCPConn, req *Request) error {
	select {
	case <-p.ctx.Done():
		return errors.New("worker pool is shutting down")

	case p.workQueue <- tcpWork{ctx, server, conn, req}:
		return nil

	default:
		// Очередь переполнена, обрабатываем соединение синхронно
		slog.Warn("TCP worker queue is full, handling connection synchronously")
		return server.Handle.TCPHandle(ctx, server, conn, req)
	}
}

// Shutdown останавливает пул воркеров
func (p *TCPWorkerPool) Shutdown() {
	p.cancel()
	close(p.workQueue)
	p.wg.Wait()
	slog.Info("TCP worker pool has been shut down")
}

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
	// RFC: [UDP ASSOCIATE] The server MAY use this information to limit access to the association.
	// Default is true for security reasons (prevents open UDP relay attacks).
	// When true, only clients with established TCP connection can use UDP.
	LimitUDP bool
	// Пулы буферов различных размеров для снижения нагрузки на GC
	SmallBufferPool  *BufferPool // 2KB буферы для TCP соединений
	MediumBufferPool *BufferPool // 8KB буферы для средних пакетов
	LargeBufferPool  *BufferPool // 64KB буферы для UDP датаграмм
	// Пул UDP соединений
	UDPConnPool *UDPConnectionPool
	// Пул воркеров для обработки TCP соединений
	TCPWorkerPool *TCPWorkerPool
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

	// Устанавливаем разумные значения TTL для кешей вместо NoExpiration
	// 30 минут для элементов, очистка каждый час
	cs := cache.New(30*time.Minute, 1*time.Hour)
	cs1 := cache.New(30*time.Minute, 1*time.Hour)
	cs2 := cache.New(30*time.Minute, 1*time.Hour)

	// Создаем пулы буферов различных размеров
	smallPool := NewBufferPool(2 * 1024)  // 2KB для TCP
	mediumPool := NewBufferPool(8 * 1024) // 8KB для средних пакетов
	largePool := NewBufferPool(64 * 1024) // 64KB для UDP датаграмм

	// Создаем пул UDP соединений с лимитом 50 соединений на каждое направление
	// и максимальным временем жизни соединения 5 минут
	udpConnPool := NewUDPConnectionPool(50, 5*time.Minute)

	// Создаем пул воркеров для обработки TCP соединений
	// Количество воркеров равно количеству процессоров (максимум 32)
	numWorkers := min(runtime.NumCPU(), 32)
	// Размер очереди - 1000 соединений
	tcpWorkerPool := NewTCPWorkerPool(context.Background(), numWorkers, 1000)

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
		SmallBufferPool:   smallPool,
		MediumBufferPool:  mediumPool,
		LargeBufferPool:   largePool,
		UDPConnPool:       udpConnPool,
		TCPWorkerPool:     tcpWorkerPool,
		LimitUDP:          true, // По умолчанию включаем ограничение для безопасности
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
		if err := r.ReplyWithError(rw, RepCommandNotSupported); err != nil {
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

	// Запускаем пул воркеров для обработки TCP соединений
	s.TCPWorkerPool.Start(s.Handle)
	defer s.TCPWorkerPool.Shutdown()

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

					// Обрабатываем соединение асинхронно
					go func(ctx context.Context, cancel context.CancelFunc, c *net.TCPConn) {
						defer func() {
							c.Close()
							cancel()
						}()

						// Выполняем первоначальное согласование протокола
						if err := s.Negotiate(c); err != nil {
							slog.Error("Failed to negotiate", slog.Any("error", err))
							return
						}

						// Получаем запрос
						r, err := s.GetRequest(c)
						if err != nil {
							slog.Error("Failed to get request", slog.Any("error", err))
							return
						}

						// Отправляем запрос в пул воркеров для обработки
						if err := s.TCPWorkerPool.Submit(ctx, s, c, r); err != nil {
							slog.Error("Failed to submit TCP connection to worker pool", slog.Any("error", err))
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

					// Используем буфер из пула вместо создания нового буфера на каждую операцию чтения
					buffer := s.LargeBufferPool.Get()
					n, addr, err := s.UDPConn.ReadFromUDP(buffer)

					if err != nil {
						// Возвращаем буфер в пул при ошибке
						s.LargeBufferPool.Put(buffer)

						// Ошибка таймаута, проверяем контекст и продолжаем
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							continue
						}
						return err
					}

					// Создаем контекст для обработки датаграммы
					dgCtx, dgCancel := context.WithCancel(serverCtx)

					// Копируем полученные данные в новый буфер нужного размера для обработки в горутине
					// Это необходимо, так как буфер будет переиспользован для следующего чтения
					dataCopy := make([]byte, n)
					copy(dataCopy, buffer[:n])

					// Возвращаем буфер в пул
					s.LargeBufferPool.Put(buffer)

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
					}(dgCtx, dgCancel, addr, dataCopy)
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
	slog.Info("Shutting down SOCKS5 server")

	// Закрываем пул UDP соединений
	if s.UDPConnPool != nil {
		s.UDPConnPool.Close()
	}

	// Очищаем пулы буферов
	if s.SmallBufferPool != nil {
		s.SmallBufferPool.Clear()
	}
	if s.MediumBufferPool != nil {
		s.MediumBufferPool.Clear()
	}
	if s.LargeBufferPool != nil {
		s.LargeBufferPool.Clear()
	}

	// Очищаем кеши
	if s.UDPExchanges != nil {
		s.UDPExchanges.Flush()
	}
	if s.AssociatedUDP != nil {
		s.AssociatedUDP.Flush()
	}
	if s.UDPSrc != nil {
		s.UDPSrc.Flush()
	}

	// Останавливаем все горутины
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

		// Создаем буферизованные reader/writer для соединений
		// Увеличиваем размер буфера для лучшей производительности
		clientReader := bufio.NewReaderSize(c, 32*1024)
		clientWriter := bufio.NewWriterSize(c, 32*1024)
		remoteReader := bufio.NewReaderSize(rc, 32*1024)
		remoteWriter := bufio.NewWriterSize(rc, 32*1024)

		// Создаем контекст с возможностью отмены
		connCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		// Вместо использования тикера для постоянного обновления таймаутов,
		// мы будем устанавливать таймауты только при реальной активности в io.Copy
		// Это позволит разрывать неактивные соединения
		hasTimeout := s.TCPTimeout != 0

		// Используем ДВА отдельных буфера для предотвращения гонок данных
		// когда оба направления копирования работают одновременно
		clientToRemoteBuf := s.MediumBufferPool.Get()
		remoteToClientBuf := s.MediumBufferPool.Get()
		defer func() {
			s.MediumBufferPool.Put(clientToRemoteBuf)
			s.MediumBufferPool.Put(remoteToClientBuf)
		}()

		// Канал для сигнализации о завершении одной из горутин
		doneCh := make(chan struct{}, 2)

		// Используем io.Copy для копирования данных между соединениями
		go func() {
			defer func() {
				doneCh <- struct{}{}
				cancel() // Отменяем контекст при завершении горутины
			}()

			// Создаем свою функцию копирования с обработкой таймаутов
			buf := make([]byte, 32*1024)
			for {
				select {
				case <-connCtx.Done():
					return
				default:
					if hasTimeout {
						// Устанавливаем таймаут чтения - соединение закроется, если не будет активности
						rc.SetReadDeadline(time.Now().Add(time.Duration(s.TCPTimeout) * time.Second))
					}

					nr, err := remoteReader.Read(buf)
					if err != nil {
						if err != io.EOF {
							slog.Debug("Error reading from remote", slog.Any("error", err))
						}
						return
					}

					if hasTimeout {
						// Обновляем таймаут записи после успешного чтения
						c.SetWriteDeadline(time.Now().Add(time.Duration(s.TCPTimeout) * time.Second))
					}

					_, err = clientWriter.Write(buf[:nr])
					if err != nil {
						slog.Debug("Error writing to client", slog.Any("error", err))
						return
					}

					// Сбрасываем буфер, чтобы отправить все данные
					err = clientWriter.Flush()
					if err != nil {
						slog.Debug("Error flushing to client", slog.Any("error", err))
						return
					}
				}
			}
		}()

		go func() {
			defer func() {
				doneCh <- struct{}{}
				cancel() // Отменяем контекст при завершении горутины
			}()

			// Создаем свою функцию копирования с обработкой таймаутов
			buf := make([]byte, 32*1024)
			for {
				select {
				case <-connCtx.Done():
					return
				default:
					if hasTimeout {
						// Устанавливаем таймаут чтения - соединение закроется, если не будет активности
						c.SetReadDeadline(time.Now().Add(time.Duration(s.TCPTimeout) * time.Second))
					}

					nr, err := clientReader.Read(buf)
					if err != nil {
						if err != io.EOF {
							slog.Debug("Error reading from client", slog.Any("error", err))
						}
						return
					}

					if hasTimeout {
						// Обновляем таймаут записи после успешного чтения
						rc.SetWriteDeadline(time.Now().Add(time.Duration(s.TCPTimeout) * time.Second))
					}

					_, err = remoteWriter.Write(buf[:nr])
					if err != nil {
						slog.Debug("Error writing to remote", slog.Any("error", err))
						return
					}

					// Сбрасываем буфер, чтобы отправить все данные
					err = remoteWriter.Flush()
					if err != nil {
						slog.Debug("Error flushing to remote", slog.Any("error", err))
						return
					}
				}
			}
		}()

		// Ожидаем завершения любой из горутин или отмены контекста
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-doneCh:
			// Ждем другую горутину или таймаут
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-doneCh:
				// Обе горутины завершились
				return nil
			case <-time.After(time.Second * 5):
				// Таймаут ожидания другой горутины
				return nil
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

	// Вместо прямого вызова DialUDP используем пул соединений
	rc, err := s.UDPConnPool.Get(laddr, dst)
	if err != nil {
		// Если не получилось получить соединение из пула или создать новое с указанным laddr,
		// пробуем создать соединение без указания локального адреса
		if !strings.Contains(err.Error(), "address already in use") && !strings.Contains(err.Error(), "can't assign requested address") {
			return errors.Wrap(err, "failed to get UDP connection from pool")
		}

		// Пробуем получить соединение из пула без указания локального адреса
		rc, err = s.UDPConnPool.Get("", dst)
		if err != nil {
			return errors.Wrap(err, "failed to get UDP connection from pool without local address")
		}

		laddr = ""
	}

	// Сохраняем локальный адрес для будущих соединений с временем жизни 30 минут
	if laddr == "" {
		s.UDPSrc.Set(src+dst, rc.LocalAddr().String(), 30*time.Minute)
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
		// Возвращаем соединение в пул в случае ошибки
		s.UDPConnPool.Put(laddr, dst, rc)
		return errors.Wrap(err, "failed to send initial data")
	}

	// Устанавливаем время жизни элемента в кеше - 30 минут
	s.UDPExchanges.Set(src+dst, ue, 30*time.Minute)

	go func(ue *UDPExchange, dst string, localAddr string) {
		defer func() {
			// Возвращаем соединение в пул при завершении горутины
			if udpConn, ok := ue.RemoteConn.(*net.UDPConn); ok {
				s.UDPConnPool.Put(localAddr, dst, udpConn)
			} else {
				ue.RemoteConn.Close() // Если не UDPConn, просто закрываем
			}

			s.UDPExchanges.Delete(ue.ClientAddr.String() + dst)
			// Удаляем запись из UDPSrc при завершении обмена данными
			s.UDPSrc.Delete(ue.ClientAddr.String() + dst)
		}()

		// Используем буфер из пула для UDP данных
		buf := s.LargeBufferPool.Get()
		defer s.LargeBufferPool.Put(buf)

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

				// Чтение в буфер из пула
				n, err := ue.RemoteConn.Read(buf)
				if err != nil {
					if !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "use of closed network connection") {
						slog.Error("Error reading from UDP connection",
							slog.String("client", ue.ClientAddr.String()),
							slog.String("remote", ue.RemoteConn.RemoteAddr().String()),
							slog.Any("error", err))
					}
					return
				}

				// Проверяем, не был ли пакет отсечен (максимальный размер UDP-датаграммы)
				if n == len(buf) {
					slog.Warn("Possible UDP datagram truncation detected",
						slog.String("client", ue.ClientAddr.String()),
						slog.String("remote", ue.RemoteConn.RemoteAddr().String()),
						slog.Int("buffer_size", len(buf)),
						slog.Int("read_bytes", n))
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

				// Создаем датаграмму для отправки клиенту
				d1 := NewDatagram(a, addr, port, buf[0:n])
				datagramBytes := d1.Bytes()

				// Добавляем обработку ошибок при отправке датаграммы
				if _, err := s.UDPConn.WriteToUDP(datagramBytes, ue.ClientAddr); err != nil {
					slog.Error("Failed to send datagram to client",
						slog.String("client", ue.ClientAddr.String()),
						slog.String("error", err.Error()))
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
	}(ue, dst, laddr)

	return nil
}
