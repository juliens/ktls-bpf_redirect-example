//go:build linux
// +build linux

package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-Wall -Wextra -g -O2" bpf proxy-sockmap.c -- -I/usr/src/linux/include

var (
	listenPort = 8081
	backend    = "127.0.0.1:8080"
)

func main() {
	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	var err error

	// Attach stream verdict
	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.HashMap.FD(),
		Program: objs.ProgVerdict,
		Attach:  ebpf.AttachSkSKBStreamVerdict,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Attach stream parser
	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.HashMap.FD(),
		Program: objs.ProgParser,
		Attach:  ebpf.AttachSkSKBStreamParser,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Start listening
	addrLn, err := net.ResolveTCPAddr("tcp", fmt.Sprintf(":%d", listenPort))
	if err != nil {
		log.Fatal(err)
	}

	listener, err := net.ListenTCP("tcp", addrLn)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	for {
		// ACCEPT CONNECTION
		inconn, err := listener.AcceptTCP()
		if err != nil {
			log.Fatal(err)
		}
		go HandleConn(inconn, objs.HashMap)
	}
}

func HandleConn(inconn *net.TCPConn, hashMap *ebpf.Map) {
	var err error
	config := &tls.Config{}
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair("./cert.pem", "./key.pem")

	server := tls.Server(inconn, config)
	err = server.Handshake()
	if err != nil {
		log.Println("Handshake", err)
		return
	}

	// DIAL + UPDATE SOCK MAP
	addr, err := net.ResolveTCPAddr("tcp", backend)
	if err != nil {
		log.Fatal(err)
	}
	outconn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		log.Fatal(err)
	}

	ofd := getFD(outconn)
	ifd := getFD(inconn)

	err = hashMap.Update(getKey(outconn), uint32(ifd), ebpf.UpdateAny)
	if err != nil {
		log.Fatal(err)
	}

	err = hashMap.Update(getKey(inconn), uint32(ofd), ebpf.UpdateAny)
	if err != nil {
		log.Fatal(err)
	}

	err = syscall.SetsockoptString(int(ifd), syscall.SOL_TCP, TCP_ULP, "tls")
	if err != nil {
		log.Println("kTLS: setsockopt(SOL_TCP, TCP_ULP) failed:", err)
	}

	err = kTLSEnable(inconn, server, TLS_TX)
	if err != nil {
		log.Fatal("ktls", err)
	}

	err = kTLSEnable(inconn, server, TLS_RX)
	if err != nil {
		log.Fatal("ktls", err)
	}

	go func() {
		b := make([]byte, 1024)
		for {
			_, err := inconn.Read(b)
			if err != nil {
				return
			}
		}
	}()

	var events [32]syscall.EpollEvent
	epfd, err := syscall.EpollCreate1(0)
	if err != nil {
		log.Fatal(err)
	}
	defer syscall.Close(epfd)

	// Use epoll(7) to wait connection close
	event := syscall.EpollEvent{Events: syscall.EPOLLRDHUP, Fd: int32(ifd)}
	for i := 0; i < 5; i++ {
		err = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, int(ifd), &event)
		if err == nil {
			break
		}
	}
	if err != nil {
		log.Fatal(err)
	}

	for {
		_, err = syscall.EpollWait(epfd, events[:], -1)
		if err == nil {
			break
		}
		errno, ok := err.(syscall.Errno)
		if !ok || errno != syscall.EINTR {
			log.Fatal(err)
		}
		log.Println("interrupted syscall, retry")
	}
	if err != nil {
		log.Fatal(err)
	}
	hashMap.Delete(getKey(inconn))
	hashMap.Delete(getKey(outconn))
	inconn.Close()
	outconn.Close()
}

func getFD(conn *net.TCPConn) uintptr {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		log.Fatal(err)
	}
	var connfd uintptr
	err = rawConn.Control(func(fd uintptr) { connfd = fd })
	if err != nil {
		log.Fatal(err)
	}
	return connfd
}

func getKey(conn *net.TCPConn) uint64 {
	_, local_port, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		log.Println(err)
		return 0
	}
	_, remote_port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		log.Println(err)
		return 0
	}

	ilocal_port, err := strconv.Atoi(local_port)
	if err != nil {
		log.Println(err)
		return 0
	}

	iremote_port, err := strconv.Atoi(remote_port)
	if err != nil {
		log.Println(err)
		return 0
	}

	key := uint64(ilocal_port<<32) | uint64(be32(iremote_port))
	return key
}

func be32(n int) uint32 {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	return binary.LittleEndian.Uint32(b[:])
}
