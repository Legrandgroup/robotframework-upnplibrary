#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import division
from __future__ import print_function

from gi.repository import GLib, GUPnP
from gi.repository import GSSDP

import threading

class UpnpDevice:
    
    """Description of an UPnP device (this is a data container without any method (the equivalent of a C-struct))"""
    
    def __init__(self,
                 hostname,
                 port, 
                 device_type,
                 friendly_name,
                 location,
                 manufacturer,
                 manufacturer_url,
                 model_description,
                 model_name,
                 model_number,
                 model_url,
                 presentation_url,
                 serial_number,
                 mac_address = None):
        self.hostname = hostname
        self.port = port
        self.device_type = device_type
        self.friendly_name = friendly_name
        self.location = location
        self.manufacturer = manufacturer
        self.manufacturer_url = manufacturer_url
        self.model_description = model_description
        self.model_name = model_name
        self.model_number = model_number
        self.model_url = model_url
        self.presentation_url = presentation_url
        self.serial_number = serial_number
        self.mac_address = mac_address

    def __repr__(self):
        if self.hostname:
            result = '[' + str(self.hostname)
            if not self.port is None:
                result += ':' + str(self.port)
            result += ']'
            
        result += '[' + str(self.friendly_name)
        result += '(' + str(self.device_type) + ')'
        if not self.mac_address is None:
            result += ',MAC=' + str(self.mac_address) + ')'
        if not self.location is None:
            result += ',LOCATION="' + str(self.location) + '"'
        if not self.presentation_url is None:
            result += ',URL="' + str(self.presentation_url) + '"'
        if self.model_description:
            result += ',MODEL="' + str(self.model_description)
            if self.model_name:
                result += '(' + str(self.model_name) + ')'
            result += '"'
        result += ']'
        return result
    
class UpnpDeviceDatabase:
    """Bonjour service database"""
    
    def __init__(self, resolve_mac = False, use_sudo_for_arping = True):
        """Initialise an empty UpnpDeviceDatabase
        
        \param resolve_mac If True, we will also resolve each entry to store the MAC address of the device together with its IP address
        \param use_sudo_for_arping Use sudo when calling arping (only used if resolve_mac is True)
        """
        self._database = {}
        self.resolve_mac = resolve_mac
        self.use_sudo_for_arping = use_sudo_for_arping

    def __repr__(self):
        temp = ''

        try:
            values = self._database.iteritems()
        except AttributeError:
            values = self._database.items()

        for (key, value) in values:
            temp += '''key:%s
value:%s
''' % (key, value)
        return temp

    def _upnp_purl_to_details(self, presentation_url):
        """Convert a presentation URL to a tuple of protocol, hostname, port, path
        \param presentation_url
        
        \return A tuple containing (protocol, hostname, port, path). Any (and possibly all) elements can be None if parsing failed
        """
        purl_proto = None
        purl_hostname = None
        purl_port = None
        purl_path = None
        purl_array_proto = presentation_url.split('//')
        if len(purl_array_proto)>1:   # Split did find '//'
            purl_proto = purl_array_proto[0].rstrip(':').lower()
            presentation_url = purl_array_proto[1]

        try:
            purl_path_sep_index = presentation_url.index('/')
            purl_path = presentation_url[purl_path_sep_index+1:]
            presentation_url = presentation_url[:purl_path_sep_index]
        except ValueError:
            pass
        
        try:
            purl_port_sep_index = presentation_url.index(':')
            purl_hostname = presentation_url[:purl_port_sep_index]
            purl_port = presentation_url[purl_port_sep_index+1:]
        except ValueError:
            # Not ':' found
            purl_hostname = presentation_url
            purl_port = None
        
        if purl_proto is None:  # Assume HTTP be default for URLs
            purl_proto = 'http'
        
        if purl_port is None:   # Handle default ports if we know them
            if purl_proto == 'http':
                purl_port = 80
            elif purl_proto == 'https':
                purl_port = 443
        
        return (purl_proto, purl_hostname, purl_port, purl_path)
        
        
    def device_available(self, cp, proxy):
        """Add one UPnP device in database
        
        \param cp A GUPnP.ControlPoint object that caught the new device event
        \param proxy An instance of GUPnP.DeviceProxy to get information about this device
        """
        # See http://lazka.github.io/pgi-docs/#GUPnP-1.0/classes/DeviceInfo.html#gupnp-deviceinfo-methods
        #print('Entering device_available() with args: [' + str(cp) + ' ,' + str(proxy) + ']')
        presentation_url = proxy.get_presentation_url()
        (purl_proto, purl_hostname, purl_port, purl_path) = self._upnp_purl_to_details(presentation_url)
        
        udn = proxy.get_udn()

        print('device_available(): Got device with hostname=' + str(purl_hostname) + ', port=' + str(purl_port))

        upnp_device = UpnpDevice(purl_hostname,
                                 purl_port,
                                 proxy.get_device_type(),
                                 proxy.get_friendly_name(),
                                 proxy.get_location(),
                                 proxy.get_manufacturer(),
                                 proxy.get_manufacturer_url(),
                                 proxy.get_model_description(),
                                 proxy.get_model_name(),
                                 proxy.get_model_number(),
                                 proxy.get_model_url(),
                                 presentation_url,
                                 proxy.get_serial_number(),
                                 mac_address = None)

#         if self.resolve_mac and not upnp_device is None:
#             upnp_device.mac_address = None
#             if protocol == 'ipv4':
#                 try:
#                     mac_address_list = arping(bonjour_service.ip_address, interface=interface_osname, use_sudo=self.use_sudo_for_arping)
#                     if len(mac_address_list) != 0:
#                         if len(mac_address_list) > 1:  # More than one MAC address... issue a warning
#                             logger.warning('Got more than one MAC address for IP address ' + str(bonjour_service.ip_address) + ': ' + str(mac_address_list) + '. Using first')
#                         bonjour_service.mac_address = mac_address_list[0]
#                 except Exception as e:
#                     if e.message != 'ArpingSubprocessFailed':   # If we got an exception related to anything else than arping subprocess...
#                         raise   # Raise the exception
#                     else:
#                         logger.warning('Arping failed for IP address ' + str(bonjour_service.ip_address) + '. Continuing anyway but MAC address will remain set to None')
#                         # Otherwise, we will just not resolve the IP address into a MAC... too bad, but maybe not that blocking
#                         # Note: this always happens when avahi-browse was launched without -l (in that cas, it might report local services, but the local IP address will not be resolved by arping as there is noone (else than us) to reply on the network interface 
#             else:
#                 logger.warning('Cannot resolve IPv6 ' + bonjour_service.ip_address + ' to MAC address (function not implemented yet)')

        key = udn
        
        msg = 'Adding '
        msg += 'service ' + str(key)
        if not upnp_device is None:
            msg += ' with details ' + str(upnp_device)
        msg += ' to internal db'
        logger.debug(msg)
        self._database[key] = upnp_device
            
        #print('service_types: ' + str(proxy.list_service_types()))    # Should be GLib.free()'d and list should also be GLib.List.free()'d
        #print('services: ' + str(proxy.list_services()))    # Should be GLib.free()'d and list should also be GLib.List.free()'d
        

    def device_unavailable(self, cp, proxy):
        """Remove one UPnP device in database
        
        \param cp A GUPnP.ControlPoint object that caught the new device event
        \param proxy An instance of GUPnP.DeviceProxy to get information about this device
        """
        # See http://lazka.github.io/pgi-docs/#GUPnP-1.0/classes/DeviceInfo.html#gupnp-deviceinfo-methods
        #print('Entering device_unavailable() with args: [' + str(cp) + ' ,' + str(proxy) + ']')
        presentation_url = proxy.get_presentation_url()
        (purl_proto, purl_hostname, purl_port, purl_path) = self._upnp_purl_to_details(presentation_url)

        udn = proxy.get_udn()

        print('device_unavailable(): Got device with hostname=' + str(purl_hostname) + ', port=' + str(purl_port))

        upnp_device = UpnpDevice(purl_hostname,
                                 purl_port,
                                 proxy.get_device_type(),
                                 proxy.get_friendly_name(),
                                 proxy.get_location(),
                                 proxy.get_manufacturer(),
                                 proxy.get_manufacturer_url(),
                                 proxy.get_model_description(),
                                 proxy.get_model_name(),
                                 proxy.get_model_number(),
                                 proxy.get_model_url(),
                                 presentation_url,
                                 proxy.get_serial_number(),
                                 mac_address = None)

        key = udn
        
        msg = 'Should remove '
        msg += 'service ' + str(key)
        if not upnp_device is None:
            msg += ' with details ' + str(upnp_device)
        msg += ' to internal db'
        logger.debug(msg)
        

        logger.debug('Removing entry ' + str(key) + ' from database')
        if key in self._database.keys():
            del self._database[key]

    def reset(self):
        """\brief Empty the database"""
        self._database = {}
        
#     def keep_only_service_name(self, service_name):
#         """\brief Filter the current database to remove all entries that do not match the specified \p service_name
#         
#         \param service_name The service name of entries to keep
#         """
#         for key in self._database.keys():
#             name = key[2]
#             if name != service_name:
#                 logger.debug('Removing non-required service named "' + name + "' from database")
#                 del self._database[key]
# 
#     def keep_only_ip_address(self, ip_address):
#         """\brief Filter the current database to remove all entries that do not match the specified \p ip_address
#         
#         \param ip_address The IP address of entries to keep
#         """
#         try:
#             records = self._database.iteritems()
#         except AttributeError:
#             records = self._database.items()
#         
#         for (key, bonjour_service) in records:
#             if not bonjour_service is None:
#                 if bonjour_service.ip_address == ip_address:
#                     logger.debug('Removing non-required IP address "' + ip_address + "' from database")
#                     del self._database[key]
# 
#     def keep_only_mac_address(self, mac_address):
#         """\brief Filter the current database to remove all entries that do not match the specified \p mac_address
#         
#         \param mac_address The MAC address of entries to keep
#         """
#         try:
#             records = self._database.iteritems()
#         except AttributeError:
#             records = self._database.items()
#         
#         for (key, bonjour_service) in records:
#             if not bonjour_service is None:
#                 if mac_normalise(bonjour_service.mac_address) == mac_normalise(mac_address):
#                     logger.debug('Removing non-required MAC address "' + mac_address + "' from database")
#                     del self._database[key]
#     
#     def export_to_tuple_list(self):
#         """\brief Export this database to a list of tuples (so that it can be processed by RobotFramework keywords)
#         
#         \return A list of tuples containing (interface, protocol, name, stype, domain, hostname, ip_address, sport, txt, flags, mac_address)
#         """
#         export = []
#         try:
#             records = self._database.iteritems()
#         except AttributeError:
#             records = self._database.items()
#         
#         for (key, bonjour_service) in records:
#             (interface_osname, protocol, name, stype, domain) = key
#             if bonjour_service:
#                 hostname = bonjour_service.hostname
#                 ip_address = bonjour_service.ip_address
#                 port = bonjour_service.port
#                 txt = bonjour_service.txt
#                 flags = bonjour_service.flags
#                 mac_address = bonjour_service.mac_address
#             else:
#                 logger.warning('Exporting a non resolved entry for service "' + str(name) + '" of type ' + str(stype))
#                 hostname = None
#                 ip_address = None
#                 port = None
#                 txt = None
#                 flags = None
#                 mac_address = None
#             export += [(interface_osname, protocol, name, stype, domain, hostname, ip_address, port, txt, flags, mac_address)]
#         
#         return export
#         
#     def import_from_tuple(self, tuple):
#         """\brief Import a record into this database from a tuples
#         
#         \param tuple A tuple containing (interface, protocol, name, stype, domain, hostname, ip_address, sport, txt, flags, mac_address), as exported into a list using export_to_tuple_list() for example 
#         """
#         (interface_osname, protocol, name, stype, domain, hostname, ip_address, port, txt, flags, mac_address) = tuple
#         key = (interface_osname, protocol, name, stype, domain)
#         bonjour_service = BonjourService(hostname, ip_address, port, txt, flags)
#         self.add(key, bonjour_service)
# 
#     def is_ip_address_in_db(self, ip_address):
#         try:
#             records = self._database.iteritems()
#         except AttributeError:
#             records = self._database.items()
#         
#         for (key, bonjour_service) in records:
#             if not bonjour_service is None:
#                 if bonjour_service.ip_address == ip_address:
#                     return True
#         return False
# 
#     def is_mac_address_in_db(self, mac_address):
#         if mac_address is None:
#             return False
#         
#         try:
#             records = self._database.iteritems()
#         except AttributeError:
#             records = self._database.items()
#         
#         for (key, bonjour_service) in records:
#             if not bonjour_service is None:
#                 if bonjour_service.mac_address == mac_address:
#                     return True
#         return False
#         
#     def get_ip_address_from_mac_address(self, searched_mac, ip_type = 'all'):
#         """\brief Check the IP address of a Bonjour device, given its MAC address
#         
#         Note: the database must have been filled with a list of devices prior to calling this method
#         An exception will be raised if there are two different matches in the db... None will be returned if there is no match
#         
#         \param searched_mac The MAC address of the device to search
#         \param ip_type The version of IP searched ('ipv4', 'ipv6' or 'all' (default)
#         
#         \return The IP address of the device (if found)
#         """
# 
#         searched_mac = mac_normalise(searched_mac, False)
#         match = None
#         
#         for key in self._database.keys():
#             protocol = key[1]
#             if ip_type == 'all' or protocol == ip_type:
#                 bonjour_service = self._database[key]
#                 if not bonjour_service is None:
#                     mac_product = bonjour_service.mac_address
#                     if not mac_product is None:
#                         mac_product = mac_normalise(mac_product, False)
#                         if searched_mac == mac_product:
#                             ip_address = self._database[key].ip_address
#                             if match is None:
#                                 match = ip_address
#                             elif match == ip_address: # Error... there are two matching entries, with different IP addresses!
#                                 raise Exception('DuplicateMACAddress')
#         return match
# 
#     def get_ip_address_from_name(self, searched_name, ip_type = 'all'):
#         """\brief Check the IP address of a Bonjour device, given its published name
#         
#         Note: the database must have been filled with a list of devices prior to calling this method
#         An exception will be raised if there are two different matches in the db... None will be returned if there is no match
#         
#         \param searched_name The MAC address of the device to search
#         \param ip_type The version of IP searched ('ipv4', 'ipv6' or 'all' (default)
#         
#         \return The IP address of the device (if found)
#         """
# 
#         match = None
#         #logger.debug('Searching for service "' + searched_name + '" to get its device IP type: ' + ip_type)
#         for key in self._database.keys():
#             protocol = key[1]
#             if ip_type == 'all' or protocol == ip_type:
#                 service_name_product = key[2]
#                 if searched_name == service_name_product:
#                     bonjour_service = self._database[key]
#                     if not bonjour_service is None:
#                         ip_address = bonjour_service.ip_address
#                         if match is None:
#                             match = ip_address
#                         elif match == ip_address: # Error... there are two matching entries, with different IP addresses!
#                             raise Exception('DuplicateServiceName')
#         return match
    
    def service_available(self, *kwargs):
        print('Entering service_available() with args: ' + str(kwargs))
    
    def service_unavailable(self, *kwargs):
        print('Entering service_unavailable() with args: ' + str(kwargs))

class UpnpLibrary:
    """Robot Framework UPnP Library"""

    ROBOT_LIBRARY_DOC_FORMAT = 'ROBOT'
    ROBOT_LIBRARY_SCOPE = 'GLOBAL'
    ROBOT_LIBRARY_VERSION = '1.0'

    def __init__(self, use_sudo_for_arping=True):
        self._service_database = None
        self._service_database_mutex = threading.Lock()    # This mutex protects writes to the _service_database attribute
        self._use_sudo_for_arping = use_sudo_for_arping

    def get_services(self, device_type = 'upnp:rootdevice', interface_name = None, ip_type = None, resolve_ip = True):
        """
        """
        
        with self._service_database_mutex:
            self._service_database = self._service_database = UpnpDeviceDatabase(resolve_mac = resolve_ip, use_sudo_for_arping = self._use_sudo_for_arping)
        
#         if service_type and service_type != '*':
#             service_type_arg = service_type
#         else:
#             service_type_arg = '-a'
# 
#         p = subprocess.Popen(['avahi-browse', '-p', '-r', '-l', '-t', service_type_arg], stdout=subprocess.PIPE)
#         self._parse_avahi_browse_output(avahi_browse_process=p, interface_name_filter=interface_name, ip_type_filter=ip_type)
        
#         with self._service_database_mutex:
#             logger.debug('Services found: ' + str(self._service_database))
#             return self._service_database.export_to_tuple_list()
        
        if interface_name is None:
            raise('InterfaceNameMandatory')
        
        try:
            ctx = GUPnP.Context.new(None, interface_name, 0)
        except TypeError:
            # Versions of gupnp older than 0.17.2 require context to be non None
            # Newer versions have deprecated use of any non-None first argument
            # See http://lazka.github.io/pgi-docs/#GUPnP-1.0/classes/Context.html#GUPnP.Context.new
            main_ctx = GLib.main_context_default() 
            ctx = GUPnP.Context.new(main_ctx, interface_name, 0)
            

        cp = GUPnP.ControlPoint.new(ctx, device_type)
        cp.set_active(True)
        cp.connect("device-proxy-available", self._service_database.device_available)
        cp.connect("device-proxy-unavailable", self._service_database.device_unavailable)
        cp.connect("service-proxy-available", self._service_database.service_available)
        cp.connect("service-proxy-unavailable", self._service_database.service_unavailable)
        print('Going to run mainloop forever')
        GLib.MainLoop().run()
        print('Finishing mainloop')

#     def get_ip(self, mac):
#         """ Get first IP address which have `mac` in UUID.
# 
#         Return IP.
# 
#         Example:
#         | Get IP | 01.23.45.67.89.ab |
#         =>
#         | ${IP} |
#         """
# 
#         ret = ''
#         self._upnp_thread.clear()
#         wait_test = {'start': self._upnp_http.generate_start_notify(eol=False)}
#         mac = ToolLibrary.mac_string(mac)
#         maxtime = time.time() + UpnpLibrary.BURST
#         while True:
#             time.sleep(UpnpLibrary.POLL_WAIT)
#             if time.time() > maxtime:
#                 raise Exception('Expected one NOTIFY/alive')
#             temp = self._upnp_thread.wait(wait_test, address=None, timeout=UpnpLibrary.BURST)
#             if temp is not None:
#                 (data, addr) = temp
#                 result = re.match('^uuid:(.*):{2}(.*)$', data['USN'])
#                 if result is not None:
#                     uuid = result.groups()[0]
#                     uuid_mac = ToolLibrary.mac_string(uuid.split('-')[-1])
#                     if uuid_mac == mac:
#                         ret = addr[0]
#                         break
#         ret = unicode(ret)
#         return ret
# 
#     def clear_queue(self):
#         """ Delete all UPnP packet received.
# 
#         Example:
#         | Clear Queue |
#         """
# 
#         self._upnp_thread.clear()
# 
#     def check_on_to_off(self, addr):
#         """ Wait a UPnP NOTIFY/byebye on `addr` until BURST time.
#         The queue has to be reset manually.
# 
#         Return data
# 
#         Example:
#         | Clear Queue |
#         | Check On To Off | ip |
#         =>
#         | ${data} |
#         """
# 
#         wait_test = {'start': self._upnp_http.generate_start_notify(eol=False), 'NTS': 'ssdp:byebye'}
#         data = self._upnp_thread.wait(wait_test, address=addr, timeout=UpnpLibrary.BURST)
#         if not data:
#             raise Exception('Expected one NOTIFY/byebye')
#         return data
# 
#     def check_on(self, addr):
#         """ Send a msearch on `addr` and wait response until BURST time.
# 
#         Return data
# 
#         Example:
#         | Check On | ip |
#         =>
#         | ${data} |
#         """
# 
#         self._upnp_thread.clear()
#         request = self._upnp_http.generate_search_request_multicast('upnp:rootdevice')
#         self._upnp_socket.send_request(request)
#         wait_test = {'start': self._upnp_http.generate_start_response(eol=False)}
#         data = self._upnp_thread.wait(wait_test, address=addr, timeout=UpnpLibrary.BURST)
#         if not data:
#             raise Exception('Expected one response')
#         return data
# 
#     def check_run(self, addr):
#         """ Wait a UPnP NOTIFY/alive on `addr` until BURST time.
# 
#         Return data
# 
#         Example:
#         | Check Run | ip | 
#         =>
#         | ${data} |
#         """
# 
#         self._upnp_thread.clear()
#         wait_test = {'start': self._upnp_http.generate_start_notify(eol=False), 'NTS': 'ssdp:alive'}
#         data = self._upnp_thread.wait(wait_test, address=addr, timeout=UpnpLibrary.BURST)
#         if not data:
#             raise Exception('Expected one NOTIFY/alive')
#         return data
# 
#     def check_stop(self, addr):
#         """ Wait no UPnP NOTIFY/alive on `addr` until BURST time.
# 
#         Example:
#         | Check Stop | ip |
#         """
# 
#         self._upnp_thread.clear()
#         wait_test = {'start': self._upnp_http.generate_start_notify(eol=False), 'NTS': 'ssdp:alive'}
#         data = self._upnp_thread.wait(wait_test, address=addr, timeout=UpnpLibrary.BURST)
#         if data:
#             raise Exception('Expected no NOTIFY')
# 
#     @staticmethod
#     def retrieve_xml(data):
#         """ Retrieve XML file from `data`.
# 
#         Return filename.
# 
#         Example:
#         | ${data} = | Check Run | ip |
#         | Retrieve Xml | ${data} | 
#         =>
#         | ${filename} |
#         """
# 
#         ret = ''
#         try:
#             data_parsed = data[0]
#             url = data_parsed['LOCATION']
#         except StandardError:
#             raise Exception('No location')
#         try:
#             ret = urllib.urlretrieve(url)[0]
#         except StandardError:
#             raise Exception('Unable to retrieve xml')
#         ret = unicode(ret)
#         return ret


if __name__ == '__main__':
    try:
        from console_logger import LOGGER as logger
    except ImportError:
        import logging
    
    logger = logging.getLogger('console_logger')
    logger.setLevel(logging.DEBUG)
    
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)
    
    try:
        input = raw_input
    except NameError:
        pass

    MAC = '00:04:74:05:00:f0'
    UL = UpnpLibrary()
    input('Press enter & "Enable UPnP/Bonjour" on web interface')
    UL.get_services(interface_name = 'eth0')
#         IP = UL.get_ip(MAC)
#         assert IP == '10.10.8.39'
#         input('Press enter & "Disable UPnP/Bonjour" on web interface')
#         UL.clear_queue()
#         DATA = UL.check_on_to_off(IP)
#         DATA = UL.check_stop(IP)
#         input('Press enter & "Enable UPnP/Bonjour" on web interface')
#         DATA = UL.check_on(IP)
#         DATA = UL.check_run(IP)
#         FILENAME = UL.retrieve_xml(DATA)
#         assert FILENAME is not None
else:
    from robot.api import logger
