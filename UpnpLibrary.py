#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import division
from __future__ import print_function

from gi.repository import GLib, GUPnP
from gi.repository import GSSDP

import re
import os

import subprocess

import threading

def guess_ip_version(ip_string):
    """ Guess the version of an IP address, check its validity
    \param ip_string A string containing an IP address
    
    \return The version of the IP protocol used (int(4) for IPv4 or int(6) for IPv6, int(0) otherwise) 
    """
    
    import socket
    
    try:
        ipv4_buffer = socket.inet_pton(socket.AF_INET, ip_string)
        return 4
    except socket.error:
        pass
    
    if socket.has_ipv6:
        try:
            ipv6_buffer = socket.inet_pton(socket.AF_INET, ip_string)
            return 6
        except socket.error:
            pass
    
    return 0

# The pythonic-version of arping below (using python scapy) is commented out because it cannot gain superuser rights via sudo, we should thus be root
# This would however be more platform-independent... instead, we run the arping command (via sudo) and parse its output
# import scapy.all
# def arping(iprange):
#     """Arping function takes IP Address or Network, returns nested mac/ip list"""
# 
#     scapy.all.conf.verb=0
#     ans,unans = scapy.all.srp(scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.all.ARP(pdst=iprange), timeout=2)
# 
#     collection = []
#     for snd, rcv in ans:
#         result = rcv.sprintf(r"%scapy.all.ARP.psrc% %scapy.all.Ether.src%").split()
#         collection.append(result)
#     return collection

"""Global variable required for function arping() below"""
arping_supports_r_i = True

def arping(ip_address, interface=None, use_sudo = True):
    """Run arping and returns a list of MAC addresses matching with the IP address provided in \p ip_address (or an empty list if there was no reply)
    
    \param ip_address The IPv4 to probe
    \param interface A network interface on which to probe (or None if we should check all network interfaces)
    \param use_sudo Use sudo to run the arping command (set this to True if privilege elevation is required)
    
    \return A list of MAC addresses matching with \p ip_address. Beware that this can be empty or even contain more than one entry
    """
    
    global arping_supports_r_i
    
    if guess_ip_version(str(ip_address)) != 4: # We have an IPv4 address
        logger.error('Arping: bad IPv4 format: ' + str(ip_address))
        raise Exception('BadIPv4Format')
    
    if use_sudo:
        arping_cmd_prefix = ['sudo']
    else:
        arping_cmd_prefix = []
    
    arping_cmd_prefix += ['arping', '-c', '1']
    
    if arping_supports_r_i:
        arping_cmd = arping_cmd_prefix + ['-r']
        if not interface is None:
            arping_cmd += ['-i', str(interface)]
        arping_cmd += [str(ip_address)]
        proc = subprocess.Popen(arping_cmd, stdout=subprocess.PIPE, stderr=open(os.devnull, 'wb'))  # Hide stderr since we may expect errors if we use the wrong args (depending on the arping version we are using)
        result=[]
        for line in iter(proc.stdout.readline,''):
            result+=[line.rstrip()]

        exitvalue = proc.wait()
        if exitvalue == 0:
            return result
        else:
            arping_supports_r_i = False
    
    # Some versions of arping coming from the iproute package do not support -r and use -I instead of -i
    if not arping_supports_r_i:
        arping_cmd = arping_cmd_prefix  # Reset the command line that we started to build above
        if not interface is None:
            arping_cmd += ['-I', str(interface)]
        arping_cmd += [str(ip_address)]
        #print(arping_cmd)
        proc = subprocess.Popen(arping_cmd, stdout=subprocess.PIPE, stderr=open(os.devnull, 'wb'))  # We also hide stderr here because sudo may complain when it cannot resolve the local machine's hostname
        result=[]
        arping_header_regexp = re.compile(r'^ARPING')
        arp_reply_template1_regexp = re.compile(r'^.*from\s+([0-9]+\.[0-9]+\.[0-9]+.[0-9]+)\s+\[([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})\]')
        arp_reply_template2_regexp = re.compile(r'^.*from\s+([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})\s+[(]([0-9]+\.[0-9]+\.[0-9]+.[0-9]+)[)]')
        arping_ip_addr = None
        arping_mac_addr = None
        for line in iter(proc.stdout.readline,''):
            line = line.rstrip()
            #print('arping:"' + str(line) + '"')
            if not re.match(arping_header_regexp, line):    # Skip the header from arping
                match = re.match(arp_reply_template1_regexp, line)
                if match:
                    arping_ip_addr = match.group(1)
                    arping_mac_addr = match.group(2)
                    break
                match = re.match(arp_reply_template2_regexp, line)
                if match:
                    arping_ip_addr = match.group(2)
                    arping_mac_addr = match.group(1)
                    break
            
        if not arping_mac_addr is None:
            if not arping_ip_addr is None:
                if arping_ip_addr != str(ip_address):
                    logger.warning('Got a mismatch on IP address reply from arping: Expected ' + str(ip_address) + ', got ' + arping_ip_addr)
            result+=[arping_mac_addr]
        
        exitvalue = proc.wait()
        if exitvalue == 0:
            return result
        else:
            arping_supports_r_i = True  # If we fail here, maybe a previous failure (that lead us to this arping does not support -r -i) was wrong... just reset our global arping guess
            raise Exception('ArpingSubprocessFailed')

def mac_normalise(mac, unix_format=True):
    """\brief Convert many notation of a MAC address to to a uniform representation
    
    \param mac The MAC address as a string
    
    \param unix_format If set to true, use the UNIX representation, so would output: 01:23:45:67:89:ab
    
    Example: mac_normalise('01.23.45.67.89.ab') == mac_normalise('01:23:45:67:89:ab') == mac_normalise('01-23-45-67-89-ab') == mac_normalise('0123456789ab') == '0123456789ab'
    mac_normalise('01.23.45.67.89.ab') == '01:23:45:67:89:ab'
    """

    ret = ''
    mac = str(mac)
    mac = mac.lower()
    mac = mac.strip()
    re_mac_one = re.compile(r'^(\w{2})[:|\-](\w{2})[:|\-](\w{2})[:|\-](\w{2})[:|\-](\w{2})[:|\-](\w{2})$')
    re_mac_two = re.compile(r'^(\w{4})\.(\w{4})\.(\w{4})$')
    re_mac_three = re.compile(r'^(\w{12})$')
    one = re.match(re_mac_one, mac)
    two = re.match(re_mac_two, mac)
    tree = re.match(re_mac_three, mac)
    if one:
        select = one.groups()
    elif two:
        select = two.groups()
    elif tree:
        select = tree.groups()
    else:
        raise Exception('InvalidMACFormat:' + str(mac))
    if unix_format:
        delim=':'
    else:
        delim=''
    return delim.join(select)
 
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
    
    def __init__(self, interface, resolve_mac = False, use_sudo_for_arping = True, db_add_event = None, db_del_event = None):
        """Initialise an empty UpnpDeviceDatabase
        
        \param interface The network interface on which devices are discovered
        \param resolve_mac If True, we will also resolve each entry to store the MAC address of the device together with its IP address
        \param use_sudo_for_arping Use sudo when calling arping (only used if resolve_mac is True)
        \param db_add_event If not None, we will invoke this threading.Event()'s set() method for every device added to the database
        \param db_del_event If not None, we will invoke this threading.Event()'s set() method for every device removed from the database
        """
        self.interface = interface
        self._database = {}
        self.resolve_mac = resolve_mac
        self.use_sudo_for_arping = use_sudo_for_arping
        self._db_add_event = db_add_event
        self._db_del_event = db_del_event

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
        
        ip_version = guess_ip_version(purl_hostname)
        if ip_version == 4:
            protocol = 'ipv4'
        elif ip_version == 6:
            protocol = 'ipv6'
        else:
            protocol = None
        
        interface_osname = self.interface
        
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

        if self.resolve_mac and not upnp_device is None:
            upnp_device.mac_address = None
            if protocol == 'ipv4':
                try:
                    mac_address_list = arping(upnp_device.hostname, interface=interface_osname, use_sudo=self.use_sudo_for_arping)
                    if len(mac_address_list) != 0:
                        if len(mac_address_list) > 1:  # More than one MAC address... issue a warning
                            logger.warning('Got more than one MAC address for IP address ' + str(upnp_device.ip_address) + ': ' + str(mac_address_list) + '. Using first')
                        upnp_device.mac_address = mac_address_list[0]
                except Exception as e:
                    if e.message != 'ArpingSubprocessFailed':   # If we got an exception related to anything else than arping subprocess...
                        raise   # Raise the exception
                    else:
                        logger.warning('Arping failed for IP address ' + str(upnp_device.ip_address) + '. Continuing anyway but MAC address will remain set to None')
                        # Otherwise, we will just not resolve the IP address into a MAC... too bad, but maybe not that blocking
            else:
                logger.warning('Cannot resolve IPv6 ' + upnp_device.ip_address + ' to MAC address (function not implemented yet)')

        key = (interface_osname, protocol, udn)
        
        msg = 'Adding '
        msg += 'service ' + str(key)
        if not upnp_device is None:
            msg += ' with details ' + str(upnp_device)
        msg += ' to internal db'
        logger.debug(msg)
        self._database[key] = upnp_device
        
        if self._db_add_event is not None:  # If there is an event to set when devices are added to the DB, do it
            self._db_add_event.set()
            
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

        ip_version = guess_ip_version(purl_hostname)
        if ip_version == 4:
            protocol = 'ipv4'
        elif ip_version == 6:
            protocol = 'ipv6'
        else:
            protocol = None
        
        interface_osname = self.interface

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

        key = (interface_osname, protocol, udn)
        
        msg = 'Should remove '
        msg += 'service ' + str(key)
        if not upnp_device is None:
            msg += ' with details ' + str(upnp_device)
        msg += ' to internal db'
        logger.debug(msg)
        

        logger.debug('Removing entry ' + str(key) + ' from database')
        if key in self._database.keys():
            del self._database[key]
            if self._db_del_event is not None:  # If there is an event to set when devices are removed from the DB, do it
                self._db_del_event.set()


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
    
    def export_to_tuple_list(self):
        """\brief Export this database to a list of tuples (so that it can be processed by RobotFramework keywords)
         
        \return A list of tuples containing (interface, protocol, udn, hostname, port, device_type, friendly_name, location, manufacturer, manufacturer_url, model_description, model_name, model_number, model_url, presentation_url, serial_number, mac_address)
        """
        export = []
        try:
            records = self._database.iteritems()
        except AttributeError:
            records = self._database.items()
         
        for (key, upnp_device) in records:
            (interface_osname, protocol, udn) = key
            if upnp_device:
                hostname = upnp_device.hostname
                port = upnp_device.port
                device_type = upnp_device.device_type
                friendly_name = upnp_device.friendly_name
                location = upnp_device.location
                manufacturer = upnp_device.manufacturer
                manufacturer_url = upnp_device.manufacturer_url
                model_description = upnp_device.model_description
                model_name = upnp_device.model_name
                model_number = upnp_device.model_number
                model_url = upnp_device.model_url
                presentation_url = upnp_device.presentation_url
                serial_number = upnp_device.serial_number
                mac_address = upnp_device.mac_address
                export += [(interface_osname, protocol, udn, hostname, port, device_type, friendly_name, location, manufacturer, manufacturer_url, model_description, model_name, model_number, model_url, presentation_url, serial_number, mac_address)]
         
        return export
         
    def import_from_tuple(self, tuple):
        """\brief Import a record into this database from a tuples
         
        \param tuple A tuple containing (interface, protocol, udn, hostname, port, device_type, friendly_name, location, manufacturer, manufacturer_url, model_description, model_name, model_number, model_url, presentation_url, serial_number, mac_address), as exported into a list using export_to_tuple_list() for example 
        """
        (interface_osname, protocol, udn, hostname, port, device_type, friendly_name, location, manufacturer, manufacturer_url, model_description, model_name, model_number, model_url, presentation_url, serial_number, mac_address) = tuple
        key = (interface_osname, protocol, udn)
        upnp_device = UpnpDevice(hostname, port, device_type, friendly_name, location, manufacturer, manufacturer_url, model_description, model_name, model_number, model_url, presentation_url, serial_number, mac_address)
        self.add(key, upnp_device)
    
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
        self._service_database_added_event = threading.Event()    # This event is set when a device is added to the database
        self._service_database_deleted_event = threading.Event()    # This event is set when a device is added to the database
        self._use_sudo_for_arping = use_sudo_for_arping

    def get_services(self, device_type = 'upnp:rootdevice', interface_name = None, ip_type = None, resolve_ip = True):
        """
        """
        
        with self._service_database_mutex:
            self._service_database = UpnpDeviceDatabase(interface = interface_name,
                                                        resolve_mac = resolve_ip,
                                                        use_sudo_for_arping = self._use_sudo_for_arping,
                                                        db_add_event = self._service_database_added_event,
                                                        db_del_event = self._service_database_deleted_event
                                                        )
        
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
        id1 = cp.connect("device-proxy-available", self._service_database.device_available)
        id2 = cp.connect("device-proxy-unavailable", self._service_database.device_unavailable)
        id3 = cp.connect("service-proxy-available", self._service_database.service_available)
        id4 = cp.connect("service-proxy-unavailable", self._service_database.service_unavailable)
        print('Going to run mainloop forever')
        _mainloop = GLib.MainLoop()
        
        def _quit_dbus_when_discovery_done():
            """This method will notify that we assume database construction is finished
            """
            logger.debug('Waiting for event')
            while self._service_database_added_event.wait(5):
                logger.debug('Got add event... resetting timer')
                self._service_database_added_event.clear()  # Reset the flag we are watching... let the DB notify us when changes are made
            
            _mainloop.quit()

        _dbus_stop_loop_thread = threading.Thread(target = _quit_dbus_when_discovery_done)    # Start a background thread that will stop the mainloop below when no new discovery occurs
        _dbus_stop_loop_thread.setDaemon(True)    # D-Bus loop should be forced to terminate when main program exits
        _dbus_stop_loop_thread.start()

        _mainloop.run()
        logger.debug('Mainloop has terminated')
        
        cp.disconnect(id1)
        cp.disconnect(id2)
        cp.disconnect(id3)
        cp.disconnect(id4)
        cp.set_active(False)
        
        logger.debug('Control point is now inactive')
        
        with self._service_database_mutex:
            logger.debug('Services found: ' + str(self._service_database))
            return self._service_database.export_to_tuple_list()

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
