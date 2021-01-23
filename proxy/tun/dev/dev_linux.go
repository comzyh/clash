// +build linux android

package dev

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/Dreamacro/clash/log"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	cloneDevicePath = "/dev/net/tun"
	ifReqSize       = unix.IFNAMSIZ + 64
)

type tunLinux struct {
	url       string
	name      string
	tunFile   *os.File
	linkCache *channel.Endpoint
	mtu       int

	autoReopen             bool // flag to always retry to open the tun file if the file is gone accidentially
	autoReopenWaitInterval int  // in seconds

	closed   bool
	stopOnce sync.Once
	wg       sync.WaitGroup // wait for goroutines to stop

	writeHandle *channel.NotificationHandle
}

// OpenTunDevice return a TunDevice according a URL
func OpenTunDevice(deviceURL url.URL, autoReopen bool) (TunDevice, error) {
	mtu, _ := strconv.ParseInt(deviceURL.Query().Get("mtu"), 0, 32)

	t := &tunLinux{
		url:                    deviceURL.String(),
		mtu:                    int(mtu),
		autoReopenWaitInterval: 3,
		autoReopen:             autoReopen,
	}

	return t.open(deviceURL)
}

func (t *tunLinux) open(deviceURL url.URL) (TunDevice, error) {
	switch deviceURL.Scheme {
	case "dev":
		return t.openDeviceByName(deviceURL.Host)
	case "fd":
		fd, err := strconv.ParseInt(deviceURL.Host, 10, 32)
		if err != nil {
			return nil, err
		}
		return t.openDeviceByFd(int(fd))
	}
	return nil, fmt.Errorf("unsupported device type `%s`", deviceURL.Scheme)
}

func (t *tunLinux) Name() string {
	return t.name
}

func (t *tunLinux) URL() string {
	return t.url
}

func (t *tunLinux) RetryToOpen() {
	log.Warnln("File is lost, retrying to open tun device %v...", t.url)

	if tunURL, err := url.Parse(t.url); err == nil {
		_, err := t.open(*tunURL)
		if err != nil {
			log.Errorln("Failed to open, err: %v", err)
		}
	}
}

func (t *tunLinux) AsLinkEndpoint() (result stack.LinkEndpoint, err error) {
	if t.linkCache != nil {
		return t.linkCache, nil
	}

	mtu, err := t.MTU()

	if err != nil {
		return nil, errors.New("unable to get device mtu")
	}

	linkEP := channel.New(512, uint32(mtu), "")

	// start Read loop. read ip packet from tun and write it to ipstack
	t.wg.Add(1)
	go func() {
		for {
			if t.tunFile == nil {
				if t.autoReopen {
					log.Warnln("tun %v is not ready, waiting...", t.name)
					time.Sleep(time.Second * time.Duration(t.autoReopenWaitInterval))
					t.RetryToOpen()
					continue
				} else {
					break
				}
			}
			packet := make([]byte, mtu)
			n, err := t.Read(packet)
			if err != nil {
				if !t.closed {
					log.Errorln("can not read from tun: %v", err)
				}
				if t.autoReopen {
					// clean up fds
					t.tunFile.Close()
					unix.Close(int(t.tunFile.Fd()))
					t.tunFile = nil
					continue
				} else {
					break // by default clash will not retry to open the tun file if any error when reading the file
				}

			}
			var p tcpip.NetworkProtocolNumber
			switch header.IPVersion(packet) {
			case header.IPv4Version:
				p = header.IPv4ProtocolNumber
			case header.IPv6Version:
				p = header.IPv6ProtocolNumber
			}
			if linkEP.IsAttached() {
				linkEP.InjectInbound(p, &stack.PacketBuffer{
					Data: buffer.View(packet[:n]).ToVectorisedView(),
				})
			} else {
				log.Debugln("received packet from tun when %s is not attached to any dispatcher.", t.Name())
			}

		}
		t.wg.Done()
		t.Close()
		log.Debugln("%v stop read loop", t.Name())
	}()

	// start write notification
	t.writeHandle = linkEP.AddNotify(t)
	t.linkCache = linkEP
	return t.linkCache, nil
}

func (t *tunLinux) Write(buff []byte) (int, error) {
	return t.tunFile.Write(buff)
}

func (t *tunLinux) Read(buff []byte) (int, error) {
	return t.tunFile.Read(buff)
}

// WriteNotify implements channel.Notification.WriteNotify.
func (t *tunLinux) WriteNotify() {
	packet, ok := t.linkCache.Read()
	if ok {
		networkHeader := packet.Pkt.NetworkHeader().View()
		transportHeader := packet.Pkt.TransportHeader().View()
		data := packet.Pkt.Data.ToView()
		buf := buffer.NewVectorisedView(len(networkHeader)+len(transportHeader)+len(data), []buffer.View{networkHeader, transportHeader, data})
		_, err := t.Write(buf.ToView())
		if err != nil {
			log.Errorln("can not write to tun: %v", err)
		}
	}
}

func (t *tunLinux) Close() {
	t.stopOnce.Do(func() {
		t.closed = true
		t.linkCache.RemoveNotify(t.writeHandle)
		t.tunFile.Close()
	})
}

// Wait wait goroutines to exit
func (t *tunLinux) Wait() {
	t.wg.Wait()
}

func (t *tunLinux) MTU() (int, error) {
	// Sometime, we can't read MTU by SIOCGIFMTU. Then we should return the preset MTU
	if t.mtu > 0 {
		return t.mtu, nil
	}
	mtu, err := t.getInterfaceMtu()
	return int(mtu), err
}

func (t *tunLinux) openDeviceByName(name string) (TunDevice, error) {
	nfd, err := unix.Open(cloneDevicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var ifr [ifReqSize]byte
	var flags uint16 = unix.IFF_TUN | unix.IFF_NO_PI
	nameBytes := []byte(name)
	if len(nameBytes) >= unix.IFNAMSIZ {
		return nil, errors.New("interface name too long")
	}
	copy(ifr[:], nameBytes)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = flags

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(nfd),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return nil, errno
	}
	err = unix.SetNonblock(nfd, true)
	if err != nil {
		return nil, err
	}

	// Note that the above -- open,ioctl,nonblock -- must happen prior to handing it to netpoll as below this line.

	t.tunFile = os.NewFile(uintptr(nfd), cloneDevicePath)
	t.name, err = t.getName()
	if err != nil {
		t.tunFile.Close()
		return nil, err
	}

	log.Infoln("Opened tun %v successfully", t.name)

	return t, nil
}

func (t *tunLinux) openDeviceByFd(fd int) (TunDevice, error) {
	var ifr struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}

	fd, err := syscall.Dup(fd)
	if err != nil {
		return nil, err
	}

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TUNGETIFF, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return nil, errno
	}

	if ifr.flags&syscall.IFF_TUN == 0 || ifr.flags&syscall.IFF_NO_PI == 0 {
		return nil, errors.New("only tun device and no pi mode supported")
	}

	nullStr := ifr.name[:]
	i := bytes.IndexByte(nullStr, 0)
	if i != -1 {
		nullStr = nullStr[:i]
	}
	t.name = string(nullStr)
	t.tunFile = os.NewFile(uintptr(fd), "/dev/tun")

	log.Infoln("Opened tun %v successfully", fd)

	return t, nil
}

func (t *tunLinux) getInterfaceMtu() (uint32, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}

	defer syscall.Close(fd)

	var ifreq struct {
		name [16]byte
		mtu  int32
		_    [20]byte
	}

	copy(ifreq.name[:], t.name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFMTU, uintptr(unsafe.Pointer(&ifreq)))
	if errno != 0 {
		return 0, errno
	}

	return uint32(ifreq.mtu), nil
}

func (t *tunLinux) getName() (string, error) {
	sysconn, err := t.tunFile.SyscallConn()
	if err != nil {
		return "", err
	}
	var ifr [ifReqSize]byte
	var errno syscall.Errno
	err = sysconn.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL,
			fd,
			uintptr(unix.TUNGETIFF),
			uintptr(unsafe.Pointer(&ifr[0])),
		)
	})
	if err != nil {
		return "", errors.New("failed to get name of TUN device: " + err.Error())
	}
	if errno != 0 {
		return "", errors.New("failed to get name of TUN device: " + errno.Error())
	}
	nullStr := ifr[:]
	i := bytes.IndexByte(nullStr, 0)
	if i != -1 {
		nullStr = nullStr[:i]
	}
	t.name = string(nullStr)
	return t.name, nil
}
