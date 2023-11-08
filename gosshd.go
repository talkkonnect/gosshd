//code reference https://github.com/Scalingo/go-ssh-examples
//BSD 2-Clause License

package gosshd

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

func SSHDaemon(username string, password string, idrsafile string, listenOn string) {

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == username && string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	privateBytes, err := ioutil.ReadFile(idrsafile)
	if err != nil {
		log.Printf("Failed to load private key (%v)", idrsafile)
		return
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Printf("Failed to parse private key")
		return
	}

	config.AddHostKey(private)

	listener, err := net.Listen("tcp", listenOn)
	if err != nil {
		log.Printf("Failed to listen on %v (%s)", listenOn, err)
	}

	log.Printf("talkkonnect remote ssh console service Listening on %v for connections.\n", listenOn)
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}

		log.Printf("New SSH connection to talkkonnect console from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		log.Println("Press Ctrl A-D to exit talkkonnect console session")
		go ssh.DiscardRequests(reqs)
		go handleChannels(chans)
	}
}

func handleChannels(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	tkConsole := exec.Command("/usr/bin/screen", "-xS", "tk")

	close := func() {
		connection.Close()
		_, err := tkConsole.Process.Wait()
		if err != nil {
			log.Printf("Failed to exit talkkonnect console (%s)", err)
		}
		log.Printf("talkkonnect console Session closed")
	}

	bashf, err := pty.Start(tkConsole)
	if err != nil {
		log.Printf("Could not start pty (%s) for talkkonnect console\n", err)
		close()
		return
	}

	var once sync.Once
	go func() {
		io.Copy(connection, bashf)
		once.Do(close)
	}()
	go func() {
		io.Copy(bashf, connection)
		once.Do(close)
	}()

	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			case "pty-req":
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				SetWinsize(bashf.Fd(), w, h)
				req.Reply(true, nil)
			case "window-change":
				w, h := parseDims(req.Payload)
				SetWinsize(bashf.Fd(), w, h)
			}
		}
	}()
}

func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}
