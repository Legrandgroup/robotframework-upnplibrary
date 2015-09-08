#!/usr/bin/python
# -*- coding: utf-8 -*-

""" Legrand MP5B """

import IN
import select
import socket
import struct

from common import LegrandError


class UpnpSocket:

    """ UPnP socket interface """

    SSDP_MULTICAST_IPV4 = '239.255.255.250'
    SSDP_MULTICAST_PORT = 1900
    DEFAULT_IFACE = None
    DEFAULT_TIMEOUT = None

    def __init__(self):
        self.iface = None
        self.timeout = None
        self.csock = None
        self.ssock = None
        self.newsock = None
        self.set_iface()
        self.set_timeout()

    def set_iface(self, iface=None):
        """ set iface """

        if iface is None:
            self.iface = UpnpSocket.DEFAULT_IFACE
        else:
            self.iface = iface

    def set_timeout(self, timeout=None):
        """ set timeout """

        if timeout is None:
            self.timeout = UpnpSocket.DEFAULT_TIMEOUT
        else:
            self.timeout = timeout

    def _create_client(self):
        """ create an UDP client socket """

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            optval = 2
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, optval)
            if self.iface is not None:
                optval = struct.pack('%ds' % (len(self.iface) + 1), self.iface)
                sock.setsockopt(socket.SOL_SOCKET, IN.SO_BINDTODEVICE, optval)
            return sock
        except StandardError:
            raise LegrandError('Unable to create client')

    def _create_server(self, socket_ipv4_address):
        """  create an UDP server socket bind to socket_ipv4_address """

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            optval = 1
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, optval)
            if self.iface is not None:
                optval = struct.pack('%ds' % (len(self.iface) + 1), self.iface)
                sock.setsockopt(socket.SOL_SOCKET, IN.SO_BINDTODEVICE, optval)
            sock.bind(socket_ipv4_address)
            return sock
        except StandardError:
            raise LegrandError('Unable to create server')

    def _join_multicast_group(self):
        """ join multicast group """

        try:
            mreq = struct.pack('4sl', socket.inet_aton(UpnpSocket.SSDP_MULTICAST_IPV4), socket.INADDR_ANY)
            self.ssock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except StandardError:
            raise LegrandError('Unable to join multicast')

    def init_sockets(self):
        """ initialize socket """

        if self.csock:
            self.csock.close()
        self.csock = self._create_client()
        if self.ssock:
            self.ssock.close()
        self.ssock = self._create_server(('', UpnpSocket.SSDP_MULTICAST_PORT))
        self._join_multicast_group()

    def cleanup_sockets(self):
        """  Clean up file/socket descriptors """

        self.csock.close()
        self.ssock.close()

    @staticmethod
    def send(sock, data):
        """ Send network data """

        if not sock:
            raise LegrandError('No socket defined')
        try:
            sock.sendto(data, (UpnpSocket.SSDP_MULTICAST_IPV4, UpnpSocket.SSDP_MULTICAST_PORT))
        except StandardError:
            raise LegrandError('Data not sent')

    def recvfrom(self, sock, size=1024):
        """ Receive network data """

        if self.timeout:
            sock.setblocking(0)
            ready = select.select([sock], [], [], self.timeout)[0]
        else:
            sock.setblocking(1)
            ready = True
        try:
            if ready:
                return sock.recvfrom(size)
            else:
                raise LegrandError('Socket not ready')
        except StandardError:
            raise LegrandError('No data received')

    def listening(self):
        """ listening for UPnP packets """

        try:
            temp = self.recvfrom(self.ssock)
        except socket.timeout:
            raise LegrandError('Socket timeout')
        else:
            return temp

    def send_request(self, request):
        """ send MSEARCH request """

        self.send(self.ssock, request)


if __name__ == '__main__':
    US = UpnpSocket()
    US.init_sockets()
    try:
        while True:
            assert US.listening() is not None
    finally:
        US.cleanup_sockets()

