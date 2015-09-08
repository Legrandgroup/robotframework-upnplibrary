#!/usr/bin/python
# -*- coding: utf-8 -*-

""" Legrand MP5B """

from __future__ import division

import Queue
import re
import time
import urllib

from upnp_http import UpnpHttp
from upnp_socket import UpnpSocket
from upnp_thread import UpnpThread

from ToolLibrary import ToolLibrary


class UpnpLibrary:

    """ robotframework UPnP library """

    ROBOT_LIBRARY_DOC_FORMAT = 'ROBOT'
    ROBOT_LIBRARY_SCOPE = 'GLOBAL'
    ROBOT_LIBRARY_VERSION = '1.0'

    BURST = 70
    POLL_WAIT = 1 / 100

    def __init__(self):

        self._upnp_socket = UpnpSocket()
        self._upnp_socket.init_sockets()
        self._queue = Queue.Queue()
        self._upnp_thread = None
        self._upnp_http = UpnpHttp()

    def start(self):
        """ Start UPnP thread.

        Example:
        | Start |
        """

        if not self._upnp_thread:
            self._upnp_thread = UpnpThread(self._upnp_socket, self._queue)
        if not self._upnp_thread.is_alive():
            try:
                self._upnp_thread.start()
            except StandardError:
                raise Exception('Thread already started')

    def stop(self):
        """ Stop UPnP thread.

        Example:
        | Stop |
        """

        if self._upnp_thread:
            if self._upnp_thread.isAlive():
                self._upnp_thread.stop()
                try:
                    self._upnp_thread.join()
                except RuntimeError:
                    raise Exception('Join deadlock')
                self._upnp_thread = None

    def get_ip(self, mac):
        """ Get first IP address which have `mac` in UUID.

        Return IP.

        Example:
        | Get IP | 01.23.45.67.89.ab |
        =>
        | ${IP} |
        """

        ret = ''
        self._upnp_thread.clear()
        wait_test = {'start': self._upnp_http.generate_start_notify(eol=False)}
        mac = ToolLibrary.mac_string(mac)
        maxtime = time.time() + UpnpLibrary.BURST
        while True:
            time.sleep(UpnpLibrary.POLL_WAIT)
            if time.time() > maxtime:
                raise Exception('Expected one NOTIFY/alive')
            temp = self._upnp_thread.wait(wait_test, address=None, timeout=UpnpLibrary.BURST)
            if temp is not None:
                (data, addr) = temp
                result = re.match('^uuid:(.*):{2}(.*)$', data['USN'])
                if result is not None:
                    uuid = result.groups()[0]
                    uuid_mac = ToolLibrary.mac_string(uuid.split('-')[-1])
                    if uuid_mac == mac:
                        ret = addr[0]
                        break
        ret = unicode(ret)
        return ret

    def clear_queue(self):
        """ Delete all UPnP packet received.

        Example:
        | Clear Queue |
        """

        self._upnp_thread.clear()

    def check_on_to_off(self, addr):
        """ Wait a UPnP NOTIFY/byebye on `addr` until BURST time.
        The queue has to be reset manually.

        Return data

        Example:
        | Clear Queue |
        | Check On To Off | ip |
        =>
        | ${data} |
        """

        wait_test = {'start': self._upnp_http.generate_start_notify(eol=False), 'NTS': 'ssdp:byebye'}
        data = self._upnp_thread.wait(wait_test, address=addr, timeout=UpnpLibrary.BURST)
        if not data:
            raise Exception('Expected one NOTIFY/byebye')
        return data

    def check_on(self, addr):
        """ Send a msearch on `addr` and wait response until BURST time.

        Return data

        Example:
        | Check On | ip |
        =>
        | ${data} |
        """

        self._upnp_thread.clear()
        request = self._upnp_http.generate_search_request_multicast('upnp:rootdevice')
        self._upnp_socket.send_request(request)
        wait_test = {'start': self._upnp_http.generate_start_response(eol=False)}
        data = self._upnp_thread.wait(wait_test, address=addr, timeout=UpnpLibrary.BURST)
        if not data:
            raise Exception('Expected one response')
        return data

    def check_run(self, addr):
        """ Wait a UPnP NOTIFY/alive on `addr` until BURST time.

        Return data

        Example:
        | Check Run | ip | 
        =>
        | ${data} |
        """

        self._upnp_thread.clear()
        wait_test = {'start': self._upnp_http.generate_start_notify(eol=False), 'NTS': 'ssdp:alive'}
        data = self._upnp_thread.wait(wait_test, address=addr, timeout=UpnpLibrary.BURST)
        if not data:
            raise Exception('Expected one NOTIFY/alive')
        return data

    def check_stop(self, addr):
        """ Wait no UPnP NOTIFY/alive on `addr` until BURST time.

        Example:
        | Check Stop | ip |
        """

        self._upnp_thread.clear()
        wait_test = {'start': self._upnp_http.generate_start_notify(eol=False), 'NTS': 'ssdp:alive'}
        data = self._upnp_thread.wait(wait_test, address=addr, timeout=UpnpLibrary.BURST)
        if data:
            raise Exception('Expected no NOTIFY')

    @staticmethod
    def retrieve_xml(data):
        """ Retrieve XML file from `data`.

        Return filename.

        Example:
        | ${data} = | Check Run | ip |
        | Retrieve Xml | ${data} | 
        =>
        | ${filename} |
        """

        ret = ''
        try:
            data_parsed = data[0]
            url = data_parsed['LOCATION']
        except StandardError:
            raise Exception('No location')
        try:
            ret = urllib.urlretrieve(url)[0]
        except StandardError:
            raise Exception('Unable to retrieve xml')
        ret = unicode(ret)
        return ret


if __name__ == '__main__':
    from console_logger import LOGGER as logger

    try:
        input = raw_input
    except NameError:
        pass

    MAC = '00:04:74:05:00:f0'
    UL = UpnpLibrary()
    try:
        UL.start()
        input('Press enter & "Enable UPnP/Bonjour" on web interface')
        IP = UL.get_ip(MAC)
        assert IP == '10.10.8.39'
        input('Press enter & "Disable UPnP/Bonjour" on web interface')
        UL.clear_queue()
        DATA = UL.check_on_to_off(IP)
        DATA = UL.check_stop(IP)
        input('Press enter & "Enable UPnP/Bonjour" on web interface')
        DATA = UL.check_on(IP)
        DATA = UL.check_run(IP)
        FILENAME = UL.retrieve_xml(DATA)
        assert FILENAME is not None
    finally:
        UL.stop()
else:
    from robot.api import logger
