#!/usr/bin/python
# -*- coding: utf-8 -*-

""" Legrand MP5B """


class UpnpHttp:

    """ generate and parse SSDP UPnP HTTP messages """

    SEP = ':'
    EOL = '\r\n'
    ALL = '*'
    SPACE = ' '
    SSDP_MULTICAST = '239.255.255.250:1900'
    VERSION = 'HTTP/1.1'
    NO_ERROR = '200 OK'

    def __init__(self, version=None):
        if not version:
            self.version = UpnpHttp.VERSION
        else:
            self.version = version

    def generate_start_notify(self, eol=True):
        """ generate start notify """

        temp = UpnpHttp.SPACE.join(['NOTIFY', UpnpHttp.ALL, self.version])
        if eol:
            temp += UpnpHttp.EOL
        return temp

    def generate_start_search(self, eol=True):
        """ generate start search """

        temp = UpnpHttp.SPACE.join(['M-SEARCH', UpnpHttp.ALL, self.version])
        if eol:
            temp += UpnpHttp.EOL
        return temp

    def generate_start_response(self, status_code=None, eol=True):
        """ generate start response """

        if status_code is None:
            status_code = UpnpHttp.NO_ERROR
        temp = UpnpHttp.SPACE.join([self.version, status_code])
        if eol:
            temp += UpnpHttp.EOL
        return temp

    def generate_start_get(self, description_path, eol=True):
        """ generate start get """

        temp = UpnpHttp.SPACE.join(['GET', description_path, self.version])
        if eol:
            temp += UpnpHttp.EOL
        return temp

    @staticmethod
    def check_intrange(data, mini, maxi):
        """ verify data is an int between mini and maxi """

        try:
            temp = int(data)
        except StandardError:
            raise Exception('Value %s is not an integer' % data)
        if temp < mini or temp > maxi:
            raise Exception('Integer %s is not in [%d;%d] range' % (data, mini, maxi))
        return temp

    @staticmethod
    def generate_header(name, value, eol=True):
        """ generate a standard header """

        temp = str(name).upper() + UpnpHttp.SEP + str(value)
        if eol:
            temp += UpnpHttp.EOL
        return temp

    def generate_device_available(
        self,
        url,
        notification_type,
        server,
        uniq_service_name,
        max_age=120,
        ):
        """ generate device available, i.e NOTIFY/alive"""

        start = self.generate_start_notify(True)
        headers = UpnpHttp.generate_header('HOST', UpnpHttp.SSDP_MULTICAST)
        headers += UpnpHttp.generate_header('CACHE-CONTROL', 'max-age = %d' % UpnpHttp.check_intrange(max_age, 1, 1800))
        headers += UpnpHttp.generate_header('LOCATION', url)
        headers += UpnpHttp.generate_header('NT', notification_type)
        headers += UpnpHttp.generate_header('NTS', 'ssdp:alive')
        headers += UpnpHttp.generate_header('SERVER', server)
        headers += UpnpHttp.generate_header('USN', uniq_service_name)
        request = start + headers + UpnpHttp.EOL
        return request

    def generate_device_unavailable(self, notification_type, uniq_service_name):
        """ generate device unavailable, i.e NOTIFY/byebye"""

        start = self.generate_start_notify(True)
        headers = UpnpHttp.generate_header('HOST', UpnpHttp.SSDP_MULTICAST)
        headers += UpnpHttp.generate_header('NT', notification_type)
        headers += UpnpHttp.generate_header('NTS', 'ssdp:byebye')
        headers += UpnpHttp.generate_header('USN', uniq_service_name)
        request = start + headers + UpnpHttp.EOL
        return request

    def generate_device_update(
        self,
        url,
        notification_type,
        uniq_service_name,
        ):
        """ generate device update, i.e NOTIFY/update"""

        start = self.generate_start_notify(True)
        headers = UpnpHttp.generate_header('HOST', UpnpHttp.SSDP_MULTICAST)
        headers += UpnpHttp.generate_header('LOCATION', url)
        headers += UpnpHttp.generate_header('NT', notification_type)
        headers += UpnpHttp.generate_header('NTS', 'ssdp:update')
        headers += UpnpHttp.generate_header('USN', uniq_service_name)
        request = start + headers + UpnpHttp.EOL
        return request

    def generate_search_request_multicast(
        self,
        search_target,
        maximum_wait=2,
        user_agent=None,
        ):
        """ generate search request, i.e M-SEARCH/multicast"""

        start = self.generate_start_search()
        headers = UpnpHttp.generate_header('HOST', UpnpHttp.SSDP_MULTICAST)
        headers += UpnpHttp.generate_header('MAN', 'ssdp:discover')
        headers += UpnpHttp.generate_header('MX', UpnpHttp.check_intrange(maximum_wait, 1, 5))
        headers += UpnpHttp.generate_header('ST', search_target)
        if user_agent is not None:
            headers += UpnpHttp.generate_header('USER_AGENT', user_agent)
        request = start + headers + UpnpHttp.EOL
        return request

    def generate_search_request_unicast(
        self,
        search_target,
        hostname,
        port_number,
        user_agent=None,
        ):
        """ generate search request, i.e M-SEARCH/unicast"""

        start = self.generate_start_search()
        headers = UpnpHttp.generate_header('HOST', UpnpHttp.SEP.join([hostname, port_number]))
        headers += UpnpHttp.generate_header('MAN', 'ssdp:discover')
        headers += UpnpHttp.generate_header('ST', search_target)
        if user_agent is not None:
            headers += UpnpHttp.generate_header('USER_AGENT', user_agent)
        request = start + headers + UpnpHttp.EOL
        return request

    def generate_search_response(
        self,
        url,
        server,
        search_target,
        uniq_service_name,
        date=None,
        max_age=120,
        ):
        """ generate search response """

        start = self.generate_start_response()
        headers = UpnpHttp.generate_header('CACHE-CONTROL', 'max-age = %d' % UpnpHttp.check_intrange(max_age, 1, 1800))
        if date is not None:
            headers += UpnpHttp.generate_header('DATE', date)
        headers += UpnpHttp.generate_header('EXT', '')
        headers += UpnpHttp.generate_header('LOCATION', url)
        headers += UpnpHttp.generate_header('SERVER', server)
        headers += UpnpHttp.generate_header('ST', search_target)
        headers += UpnpHttp.generate_header('USN', uniq_service_name)
        request = start + headers + UpnpHttp.EOL
        return request

    def generate_get_description(
        self,
        description_path,
        hostname,
        port_number=80,
        language=None,
        ):
        """ generate get description, i.e GET"""

        start = self.generate_start_get(description_path)
        headers = UpnpHttp.generate_header('HOST', UpnpHttp.SEP.join([hostname, port_number]))
        if language is not None:
            headers += UpnpHttp.generate_header('ACCEPT-LANGUAGE', language)
        request = start + headers + UpnpHttp.EOL
        return request

    @staticmethod
    def parse_data(data):
        """ parse received data """

        data_dict = {}
        lines = data.split(UpnpHttp.EOL)
        data_dict['start'] = lines[0]  # start key is used for the first line
        for line in lines[1:]:
            try:
                (name, value) = line.split(UpnpHttp.SEP, 1)
                name = name.upper()
                name.strip()
            except StandardError:
                pass
            else:
                data_dict[name] = value.strip()
        return data_dict

    @staticmethod
    def parse_location(url):
        """ parse url """

        host = False
        page = False
        try:
            (method, temp) = url.split('://', 1)
            (host, page) = temp.split('/', 1)
        except StandardError:
            page = url
        return (method, host, page)


if __name__ == '__main__':
    UH = UpnpHttp('HTTP/1.0')
    assert 'NOTIFY * HTTP/1.0' == UH.generate_start_notify(eol=False)
    assert 'M-SEARCH * HTTP/1.0' == UH.generate_start_search(eol=False)
    assert 'HTTP/1.0 200 OK' == UH.generate_start_response(eol=False)
    assert 'GET /path HTTP/1.0' == UH.generate_start_get('/path', eol=False)
