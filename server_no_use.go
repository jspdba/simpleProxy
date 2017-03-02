package proxy

import (
	"io"
	"log"
	"net"
	"strconv"
	"errors"
	"time"
)


var (
	errAddrType      = errors.New("socks addr type not supported")
	errVer           = errors.New("socks version not supported")
	errMethod        = errors.New("socks only support 1 method now")
	errAuthExtraData = errors.New("socks authentication get extra data")
	errReqExtraData  = errors.New("socks request get extra data")
	errCmd           = errors.New("socks command not supported")

	readTimeout      = 10*time.Second
)

func run() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	l, err := net.Listen("tcp", ":8081")
	if err != nil {
		log.Panic(err)
	}
	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}
		go handleClientRequest(client)
	}
}
//设置读超时时间
func SetReadTimeout(c net.Conn) {
	if readTimeout != 0 {
		c.SetReadDeadline(time.Now().Add(readTimeout))
	}
}
func handShake(conn net.Conn) (err error) {
	const (
		idVer     = 0
		idNmethod = 1
	)
	// version identification and method selection message in theory can have
	// at most 256 methods, plus version and nmethod field in total 258 bytes
	// the current rfc defines only 3 authentication methods (plus 2 reserved),
	// so it won't be such long in practice

	buf := make([]byte, 258)

	var n int
	//SetReadTimeout(conn)
	// make sure we get the nmethod field
	if n, err = io.ReadAtLeast(conn, buf, idNmethod+1); err != nil {
		panic(err)
		return
	}
	if buf[idVer] != 0x05 {
		log.Println(buf[idVer])
		return errVer
	}
	nmethod := int(buf[idNmethod])
	msgLen := nmethod + 2

	log.Println(nmethod,msgLen)
	if n == msgLen { // handshake done, common case
		// do nothing, jump directly to send confirmation
	} else if n < msgLen { // has more methods to read, rare case
		if _, err = io.ReadFull(conn, buf[n:msgLen]); err != nil {
			return
		}
	} else { // error, should not get extra data
		return errAuthExtraData
	}
	// send confirmation: version 5, no authentication required
	_, err = conn.Write([]byte{0x05, 0})
	return
}

func handleClientRequest(client net.Conn) {
	if client == nil {
		return
	}
	defer client.Close()
	var b [1024]byte
	n, err := client.Read(b[:])
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("VER===%#x",b[0])
	nmethod := int(b[1])
	log.Printf("NMETHODS===%d",nmethod)
	log.Printf("METHODS===%#x",b[2])
	handShake(client)

	if b[0] == 0x05 {//only process socket5
		//client response no auth
		//client.Write([]byte{0x05, 0x00})
		n, err = client.Read(b[:])
		log.Printf("CMD===%#x",b[1])
		log.Printf("RSV===%#x",b[2])
		var host, port string
		switch b[3] {
		case 0x01:
			//IP V4
			host = net.IPv4(b[4], b[5], b[6], b[7]).String()
		case 0x03: //address
			host = string(b[5 : n-2]) //b[4] length of host
		case 0x04: //ip v6
			host = net.IP{b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]}.String()
		}
		log.Printf("%b,%b",int(b[n-2]<<8),int(b[n-1]))
		port = strconv.Itoa(int(b[n-2]<<8) | int(b[n-1]))
		log.Println(host,port)
		server, err := net.Dial("tcp", net.JoinHostPort(host, port))
		if err != nil {
			log.Println(err)
			return
		}
		defer server.Close()
		client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) //success and send data redirect
		go io.Copy(server, client)
		io.Copy(client, server)
	}
}