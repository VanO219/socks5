package socks5

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"

	"github.com/VanO219/errors"
)

// ParseAddress format address x.x.x.x:xx to raw address.
// addr contains domain length
func ParseAddress(address string) (a byte, addr []byte, port []byte, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.ParseAddress()")
	}()

	var h, p string
	h, p, err = net.SplitHostPort(address)
	if err != nil {
		return
	}

	ip := net.ParseIP(h)
	if ip4 := ip.To4(); ip4 != nil {
		a = ATYPIPv4
		addr = []byte(ip4)
	} else if ip6 := ip.To16(); ip6 != nil {
		a = ATYPIPv6
		addr = []byte(ip6)
	} else {
		a = ATYPDomain
		addr = []byte{byte(len(h))}
		addr = append(addr, []byte(h)...)
	}

	i, err := strconv.Atoi(p)
	if err != nil {
		return
	}

	port = make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(i))
	return
}

// bytes to address
// addr contains domain length
func ParseBytesAddress(b []byte) (a byte, addr []byte, port []byte, err error) {
	defer func() {
		err = errors.Wrap(err, "socks5.ParseBytesAddress()")
	}()

	if len(b) < 1 {
		err = errors.New("Invalid address: too short")
		return
	}

	a = b[0]
	if a == ATYPIPv4 {
		if len(b) < 1+4+2 {
			err = errors.New("Invalid IPv4 address: too short")
			return
		}
		addr = b[1 : 1+4]
		port = b[1+4 : 1+4+2]
		return
	}

	if a == ATYPIPv6 {
		if len(b) < 1+16+2 {
			err = errors.New("Invalid IPv6 address: too short")
			return
		}
		addr = b[1 : 1+16]
		port = b[1+16 : 1+16+2]
		return
	}

	if a == ATYPDomain {
		if len(b) < 1+1 {
			err = errors.New("Invalid domain address: too short")
			return
		}
		l := int(b[1])
		if len(b) < 1+1+l+2 {
			err = errors.New("Invalid domain address: domain name too short")
			return
		}
		addr = b[1 : 1+1+l]
		port = b[1+1+l : 1+1+l+2]
		return
	}

	err = errors.New("Invalid address type")
	return
}

// ToAddress format raw address to x.x.x.x:xx
// addr contains domain length
func ToAddress(a byte, addr []byte, port []byte) string {
	var h, p string
	if a == ATYPIPv4 || a == ATYPIPv6 {
		h = net.IP(addr).String()
	}
	if a == ATYPDomain {
		if len(addr) < 1 {
			return ""
		}
		if len(addr) < int(addr[0])+1 {
			return ""
		}
		h = string(addr[1:])
	}
	p = strconv.Itoa(int(binary.BigEndian.Uint16(port)))
	return net.JoinHostPort(h, p)
}

// Address return request address like ip:xx
func (r *Request) Address() string {
	var s string
	if r.Atyp == ATYPDomain {
		s = bytes.NewBuffer(r.DstAddr[1:]).String()
	} else {
		s = net.IP(r.DstAddr).String()
	}
	p := strconv.Itoa(int(binary.BigEndian.Uint16(r.DstPort)))
	return net.JoinHostPort(s, p)
}

// Address return request address like ip:xx
func (r *Reply) Address() string {
	var s string
	if r.Atyp == ATYPDomain {
		s = bytes.NewBuffer(r.BndAddr[1:]).String()
	} else {
		s = net.IP(r.BndAddr).String()
	}
	p := strconv.Itoa(int(binary.BigEndian.Uint16(r.BndPort)))
	return net.JoinHostPort(s, p)
}

// Address return datagram address like ip:xx
func (d *Datagram) Address() string {
	var s string
	if d.Atyp == ATYPDomain {
		s = bytes.NewBuffer(d.DstAddr[1:]).String()
	} else {
		s = net.IP(d.DstAddr).String()
	}
	p := strconv.Itoa(int(binary.BigEndian.Uint16(d.DstPort)))
	return net.JoinHostPort(s, p)
}

// WriteAll записывает все данные в writer, обрабатывая частичные записи
// Эта функция гарантирует, что все данные будут записаны полностью или
// вернется ошибка, если операция не может быть завершена
func WriteAll(w io.Writer, data []byte) (int, error) {
	total := 0
	for total < len(data) {
		n, err := w.Write(data[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 { // Избегаем бесконечного цикла при нулевой записи
			return total, errors.New("write returned 0 bytes written without error")
		}
	}
	return total, nil
}
