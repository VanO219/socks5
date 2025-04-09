package socks5

import (
	"net"

	"github.com/VanO219/errors"
)

var Resolve func(network string, addr string) (net.Addr, error) = func(network string, addr string) (net.Addr, error) {
	if network == "tcp" {
		return net.ResolveTCPAddr("tcp", addr)
	}
	return net.ResolveUDPAddr("udp", addr)
}

var DialTCP func(laddr, raddr string) (net.Conn, error) = func(laddr, raddr string) (net.Conn, error) {
	var la *net.TCPAddr
	if laddr != "" {
		var err error
		la, err = net.ResolveTCPAddr("tcp", laddr)
		if err != nil {
			return nil, errors.Wrap(err, "init.DialTCP: resolve local address failed")
		}
	}

	ra, err := net.ResolveTCPAddr("tcp", raddr)
	if err != nil {
		return nil, errors.Wrap(err, "init.DialTCP: resolve remote address failed")
	}

	return net.DialTCP("tcp", la, ra)
}

var DialUDP func(laddr, raddr string) (net.Conn, error) = func(laddr, raddr string) (net.Conn, error) {
	var la *net.UDPAddr
	if laddr != "" {
		var err error
		la, err = net.ResolveUDPAddr("udp", laddr)
		if err != nil {
			return nil, errors.Wrap(err, "init.DialUDP: resolve local address failed")
		}
	}

	ra, err := net.ResolveUDPAddr("udp", raddr)
	if err != nil {
		return nil, errors.Wrap(err, "init.DialUDP: resolve remote address failed")
	}

	return net.DialUDP("udp", la, ra)
}
