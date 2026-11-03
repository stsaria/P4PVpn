import asyncio
from asyncio import BaseEventLoop
from collections.abc import Awaitable, Callable
import os
import fcntl
import struct
import socket
import subprocess

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
IFF_UP = 0x0001

NETLINK_ROUTE = 0
RTM_NEWADDR = 20
NLM_F_REQUEST = 0x0001
NLM_F_CREATE = 0x0400
NLM_F_EXCL = 0x0200
NLM_F_ACK = 0x0004
AF_INET6 = 10
IFA_LOCAL = 2

class LinuxTunDevice:
    def __init__(self, ip:str, onRecvedFunc:Callable[[str, bytes], Awaitable[None]], prefixLen:int=64, ifname:str="tun0", readBufferSize:int = 1024, loop:BaseEventLoop | None = None):
        if prefixLen <= 0:
            raise ValueError("prefixLen > 0")
        elif readBufferSize <= 0:
            raise ValueError("readBufferSize > 0")
        elif os.geteuid() != 0:
            raise PermissionError("You must create the instance with root permission.")
        
        self._ip:str = ip
        self._onRecvedFunc:Callable[[str, bytes], Awaitable[None]] = onRecvedFunc
        self._prefixLen:int = prefixLen
        self._ifname:str = ifname
        self._readBufferSize:int = readBufferSize
        self._loop:BaseEventLoop | None = loop or asyncio.get_running_loop()
        self._fd:int = self._createAndConfigure()

    def _createAndConfigure(self) -> int:
        fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack("16sH", self._ifname.encode('utf-8'), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(fd, TUNSETIFF, ifr)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            ifrFlags = struct.pack('16sH', self._ifname.encode('utf-8'), 0)
            res = fcntl.ioctl(s.fileno(), SIOCGIFFLAGS, ifrFlags)
            _, flags = struct.unpack('16sH', res)
            
            flags |= IFF_UP
            ifrFlags = struct.pack('16sH', self._ifname.encode('utf-8'), flags)
            fcntl.ioctl(s.fileno(), SIOCSIFFLAGS, ifrFlags)
        
        self._setIpv6Address()

        return fd

    def _setIpv6Address(self) -> None:
        ifindex = socket.if_nametoindex(self._ifname)
        ipBytes = socket.inet_pton(socket.AF_INET6, self._ip)

        rtaLen = 4 + len(ipBytes)
        nlaLocal = struct.pack("H H 16s", rtaLen, IFA_LOCAL, ipBytes)

        ifAddrMsg = struct.pack("B B B B I", AF_INET6, self._prefixLen, 0, 0, ifindex)

        body = ifAddrMsg + nlaLocal
        nlmsgLen = 16 + len(body)
        nlmsgHeaders = struct.pack("I H H I I", nlmsgLen, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, 1, 0)
        
        msg = nlmsgHeaders + body

        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE) as ns:
            ns.bind((0, 0))
            ns.sendall(msg)
            ns.recv(1024)
    
    def write(self, data:bytes):
        os.write(self._fd, data)

    def begin(self):
        os.set_blocking(self._fd, False)

        def readCallback():
            try:
                packet = os.read(self._fd, self._readBufferSize)
                if len(packet) < 40:
                    return
                version = packet[0] >> 4
                if version == 6:
                    destIpBytes = packet[24:40]
                    destIp = socket.inet_ntop(socket.AF_INET6, destIpBytes)
                    asyncio.create_task(self._onRecvedFunc(destIp, packet))
            except BlockingIOError:
                pass
        self._loop.add_reader(self._fd, readCallback)
    def end(self):
        try:
            self._loop.remove_reader(self._fd)
            os.close(self._fd)
        except Exception:
            pass