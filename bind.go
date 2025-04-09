package socks5

import (
	"log/slog"
	"net"

	"github.com/VanO219/errors"
)

// TODO: Реализовать полную поддержку команды BIND согласно RFC1928
// BIND используется для протоколов, требующих от сервера подключения к клиенту
// Например, для FTP в активном режиме
func (r *Request) bind(c net.Conn) error {
	slog.Warn("BIND command requested but not implemented",
		slog.String("address", r.Address()),
		slog.String("remote_addr", c.RemoteAddr().String()))
	return errors.New("BIND command is not supported in this implementation")
}
