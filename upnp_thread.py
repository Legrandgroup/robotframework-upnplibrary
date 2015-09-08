#!/usr/bin/python
# -*- coding: utf-8 -*-

""" Legrand MP5B """

from __future__ import division

import Queue
import threading
import time

from upnp_http import UpnpHttp

from common import LegrandError


class UpnpThread(threading.Thread):

    """ socket producer thread """

    SELECT_WAIT = 1 / 100
    EVENT_WAIT = 1 / 100
    POLL_WAIT = 1 / 100

    def __init__(self, upnp_socket, queue):
        threading.Thread.__init__(self)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._upnp_socket = upnp_socket
        self._upnp_socket.set_timeout(UpnpThread.SELECT_WAIT)
        self._queue = queue

    def run(self):
        """ override Thread.run """

        while not self._stop.is_set():
            try:
                temp = self._upnp_socket.listening()
            except LegrandError:
                pass
            else:
                self._queue.put(temp)
            self._stop.wait(UpnpThread.EVENT_WAIT)

    def stop(self):
        """ stopping Thread """

        self._stop.set()

    @staticmethod
    def compare(test, data):
        """ verify that user test dictionnary is a subset of data dictionnary parsed from network """

        status = True
        message = None
        if 'start' in test:
            if test['start'] == data['start']:
                for key in test.keys():
                    if key == 'start':
                        continue
                    if key in data:
                        if test[key] != data[key]:
                            status &= False
                            message = 'key test (%s) != parsed (%s)' % (test[key], data[key])
                    else:
                        status &= False
                        message = 'key (%s) not in (%s)' % (key, data)
            else:
                status &= False
                message = 'start test (%s) != parsed (%s)' % (test['start'], data['start'])
        else:
            status &= False
            message = 'no start in test (%s)' % test
        if not message:
            message = 'OK test is a subset of parsed data'
        return (status, message)

    def wait(
        self,
        test,
        address=None,
        timeout=60,
        ):
        """ wait that test is see until timeout """

        ret = None
        timeout = int(timeout)
        maxtime = time.time() + timeout
        while True:
            time.sleep(UpnpThread.POLL_WAIT)
            if time.time() > maxtime:
                break
            try:
                (data, addr) = self._queue.get_nowait()
            except Queue.Empty:
                pass
            else:
                self._queue.task_done()
                logger.debug('Data (%s,%s)' % (data, addr))
                logger.debug('Filter (%s,%s)' % (test, address))
                if not address or address == addr[0]:
                    data_parsed = UpnpHttp.parse_data(data)
                    logger.debug('Parsed data %s' % data_parsed)
                    (status, message) = self.compare(test, data_parsed)
                    logger.debug('Result (%s,%s)' % (status, message))
                    if status:
                        ret = (data_parsed, addr)
                        break
        return ret

    def clear(self):
        """ clear the queue """

        while True:
            try:
                self._queue.get_nowait()
            except:

                    # Queue.Empty

                break


if __name__ == '__main__':
    from console_logger import LOGGER as logger
    from upnp_socket import UpnpSocket
    US = UpnpSocket()
    US.init_sockets()
    QUEUE = Queue.Queue()
    UT = UpnpThread(US, QUEUE)
    try:
        UT.start()
        while True:
            UT.wait({'start': ''})
        UT.clear()
    finally:
        UT.stop()
else:
    from robot.api import logger
