#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import division

import re
import sys
import os

import subprocess

import threading

if __name__ != '__main__':
    from robot.api import logger
else:
    try:
        from console_logger import LOGGER as logger
    except ImportError:
        import logging

        logger = logging.getLogger('console_logger')
        logger.setLevel(logging.DEBUG)
        
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(handler)

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

def arping(ip_address, interface=None, use_sudo = True, logger = None):
    """Run arping and returns a list of MAC addresses matching with the IP address provided in \p ip_address (or an empty list if there was no reply)
    
    \param ip_address The IPv4 to probe
    \param interface A network interface on which to probe (or None if we should check all network interfaces)
    \param use_sudo Use sudo to run the arping command (set this to True if privilege elevation is required)
    
    \return A list of MAC addresses matching with \p ip_address. Beware that this can be empty or even contain more than one entry
    """
    
    global arping_supports_r_i
    
    if guess_ip_version(str(ip_address)) != 4: # We have an IPv4 address
        if logger is not None:
            logger.warn('Arping: bad IPv4 format: ' + str(ip_address))
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
        #print('Result for arping:"' + str(result) + '"')
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
        #print('Running command: ' + str(arping_cmd))
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
                #print('Trying to match line: "' + str(line) + '"')
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
                if logger is not None:
                    logger.debug('Got no MAC address match on arping line "' + str(line= + '"'))
        
        if logger is not None:
            logger.debug('Arping returned: arping_mac_addr=' + str(arping_mac_addr) + ' for arping_ip_addr=' + str(arping_ip_addr))
        if not arping_mac_addr is None:
            if not arping_ip_addr is None:
                if arping_ip_addr != str(ip_address):
                    if logger is not None:
                        logger.warn('Got a mismatch on IP address reply from arping: Expected ' + str(ip_address) + ', got ' + arping_ip_addr)
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

class UpnpBrowseDeviceEvent:
    
    """Class representing a device browse event (as output by script UpnpBrowse.py)"""
    
    def __init__(self, entry_array):
        """\brief Class constructor
        
        \param entry_array One line of output as provided by UpnpBrowse, formatted as a list of UTF-8 encoded strings
        
        This method will raise exceptions if the entry_array cannot be parsed correctly, otherwise the UpnpBrowseDeviceEvent will be constructed properly.
        
        The properties that are populated inside this class are:
        self.interface The network interface on which the device has been discovered (following the OS notation, eg: 'eth0')
        self.udn The UDN of the UPnP device (unique ID)
        self.friendly_name The UPnP friendly name (displayed when browsing the network neighborhood)
        self.location The URL of the xml device description
        self.manufacturer The device manufacturer (if any)
        self.manufacturer_url The device manufacturer's online URL (if any)
        self.model_description A (human readable) model description of the device (if any)
        self.model_name The model name of the device (if any)
        self.model_number The model number (usually a product version, or revision) of the device (if any)
        self.model_url An URL to an online device model description (if any)
        self.presentation_url The URL to connect to when double-clicking on the device, usually showing status or configuration webpages (if any)
        self.serial_number The serial number of the device, often matching with the MAC address (if any)
        """
        
        if entry_array is None:
            raise Exception('InvalidEntry')
        
        type = entry_array[0]
        self._input = entry_array
        
        if type == '+':
            self.event = 'add'
        elif type == '-':
            self.event = 'del'
        else:
            raise Exception('UnknownType:' + type)
        
        if self.event == 'add' and len(entry_array) != 14:
            raise Exception('InvalidEntry')
        #else:
        #    print('Processing new entry: ' + str(entry_array))
        
        self.interface = UpnpBrowseDeviceEvent.unescape_upnpbrowse_string(entry_array[1])
        if not self.interface:
            raise Exception('InvalidEntry')
        self.udn = UpnpBrowseDeviceEvent.unescape_upnpbrowse_string(entry_array[2])
        if not self.udn:
            raise Exception('InvalidEntry')
        
        self.device_type = None
        self.friendly_name = None
        self.location = None
        self.manufacturer = None
        self.manufacturer_url = None
        self.model_description = None
        self.model_name = None
        self.model_number = None
        self.model_url = None
        self.presentation_url = None
        self.serial_number = None
        
        try:
            self.device_type = UpnpBrowseDeviceEvent.unescape_upnpbrowse_string(entry_array[3])
            if not self.device_type:
                if self.event == 'add':
                    raise Exception('InvalidEntry')
                self.device_type = None
            self.friendly_name = UpnpBrowseDeviceEvent.unescape_upnpbrowse_string(entry_array[4])
            if not self.friendly_name:
                if self.event == 'add':
                    raise Exception('InvalidEntry')
                self.friendly_name = None
            self.location = UpnpBrowseDeviceEvent.unescape_upnpbrowse_string(entry_array[5])
            if not self.location:
                self.location = None
            self.manufacturer = UpnpBrowseDeviceEvent.unescape_upnpbrowse_string(entry_array[6])
            if not self.manufacturer:
                self.manufacturer = None
            self.manufacturer_url = UpnpBrowseDeviceEvent.unescape_upnpbrowse_string(entry_array[7])
            if not self.manufacturer_url:
                self.manufacturer_url = None
            self.model_description = UpnpBrowseDeviceEvent.unescape_upnpbrowse_string(entry_array[8])
            if not self.model_description:
                self.model_description = None
            self.model_name = UpnpBrowseDeviceEvent.unescape_upnpbrowse_string(entry_array[9])
            if not self.model_name:
                self.model_name = None
            self.model_number = UpnpBrowseDeviceEvent.unescape_upnpbrowse_string(entry_array[10])
            if not self.model_number:
                self.model_number = None
            self.model_url = UpnpBrowseDeviceEvent.unescape_upnpbrowse_string(entry_array[11])
            if not self.model_url:
                self.model_url = None
            self.presentation_url = UpnpBrowseDeviceEvent.unescape_upnpbrowse_string(entry_array[12])
            if not self.presentation_url:
                self.presentation_url = None
            self.serial_number = UpnpBrowseDeviceEvent.unescape_upnpbrowse_string(entry_array[13])
            if not self.serial_number:
                self.serial_number = None
        except IndexError as e:
            if self.event == 'add':
                raise	# Only propagate array out of bound exception for 'add' events (not for 'del' events that often have incomplete fields)
        self.txt_missing_end = False
    
    def continued_on_next_line(self):
        """\brief Are there more lines required to fill-in this device description
        
        \return True if there are more lines required to fill-in this device description. In such case, the additional lines can be provided by subsequent calls to method add_line() below
        """
        return self.txt_missing_end
        
    def add_line(self, line):
        """\brief Provided additional lines to fill-in this device description. This is not supported because UpnpBrowser's output never span multiple lines, but it is kept here for homogeneous interface with the Robotframework BonjourLibrary
        
        \param line A new line to process, encoded as UTF-8 (without the terminating carriage return)
        """
        raise Exception('ExtraInputLine')
    
    @staticmethod
    def unescape_upnpbrowse_string(input):
        """\brief Unescape all escaped characters in string \p input
        
        \param input String to unescape
        
        \return The unescaped string (avahi-browse escaped bytes will lead to an UTF-8 encoded returned string)
        """
        output = ''
        espace_pos = input.find('\\')
        while espace_pos != -1:
            new_chunk = input[espace_pos+1:]
            output += input[:espace_pos]
            #print(output + '==>' + new_chunk)
            try:
                escaped_char = int(new_chunk[0]) * 100 + int(new_chunk[1]) * 10 + int(new_chunk[2])	# Fetch 3 following digits and convert them to a decimal value
                output += chr(escaped_char)	# Append escaped character to output (note: if escaped_char is not a byte (>255 for example), an exception will be raised here
                new_chunk = new_chunk[3:]	# Skip the 3 characters that make the escaped ASCII value
            except:
                output += '\\'	# This was not an escaped character... re-insert the '\'
            
            input = new_chunk
            espace_pos = input.find('\\')
        
        output += input
        return output
    
    def __repr__(self):
        if self.event == 'add':
            output = '+'
        elif self.event == 'update':
            output = '!'
        elif self.event == 'del':
            output = '-'
        else:
            output = '?'
        output += '[if=' + str(self.interface) + ']: "' + str(self.udn) + '"'
        if self.presentation_url:
            output += ' '+ str(self.presentation_url)
        if self.friendly_name:
            output += '(' + str(self.friendly_name)
            output += ')'
        return output

class UpnpDevice:
    
    """Description of an UPnP device (this is a data container without any method (the equivalent of a C-struct))"""
    
    def __init__(self,
                 hostname,
                 ip_address,
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
        self.ip_address = ip_address
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
        if self.ip_address:
            result = '[' + str(self.ip_address)
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
    """UPnP service database"""
    
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

    @staticmethod
    def _upnp_purl_to_details(presentation_url):
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
    
    @staticmethod
    def _hostname_to_ip_address(ip_version, hostname):
        """Resolve a hostname to an IP address
        
        \param ip_version 4 to resolve to an IPv4 or 6 to resolve to an IPv6
        \param hostname The hostname to be resolved
        
        \return The IP address of the provided \p hostname
        """
        hostname_contains_ip_version = guess_ip_version(hostname)
        if ip_version == 4 and hostname_contains_ip_version == 4:
            return hostname
        if ip_version == 6 and hostname_contains_ip_version == 6:
            return hostname
        raise('HostnameResolutionNotSupported')
        
    def add(self, key, upnp_device):
        """Add one UPnP device in database
        
        \param key A tuple containing the description of the UPnP device (interface, protocol, udn) (note that interface is a string containing the interface name following the OS designation)
        \param upnp_device An instance of UpnpDevice to add in the database for this \p key
        """
        
        (interface_osname, protocol, udn) = key
        msg = 'Adding device ' + str(key) + ' with details ' + str(upnp_device) + ' to internal db'
        logger.debug(msg)
        if self.resolve_mac and not upnp_device is None:
            upnp_device.mac_address = None
            if protocol == 'ipv4':
                try:
                    phys_interface_osname = interface_osname.split(':')[0]	# Extract the physical interface name for arping (eg: arping should be done on 'eth1', not on 'eth1:avahi')
                    mac_address_list = arping(upnp_device.ip_address, phys_interface_osname, use_sudo=self.use_sudo_for_arping, logger=logger)
                    if len(mac_address_list) != 0:
                        if len(mac_address_list) > 1:  # More than one MAC address... issue a warning
                            logger.warn('Got more than one MAC address for host ' + str(upnp_device.ip_address) + ': ' + str(mac_address_list) + '. Using first')
                        upnp_device.mac_address = mac_address_list[0]
                except Exception as e:
                    if e.message != 'ArpingSubprocessFailed':   # If we got an exception related to anything else than arping subprocess...
                        raise   # Raise the exception
                    else:
                        logger.warn('Arping failed for IP address ' + str(upnp_device.ip_address) + '. Continuing anyway but MAC address will remain set to None')
                        # Otherwise, we will just not resolve the IP address into a MAC... too bad, but maybe not that blocking
            else:
                logger.warn('Cannot resolve IPv6 ' + upnp_device.ip_address + ' to MAC address (function not implemented yet)')
            
        self._database[key] = upnp_device

    def remove(self, key):
        """Remove one UPnP device from database
        
        \param key A tuple containing (interface, protocol, udn), which is the key of the record to delete from the database 
        """

        logger.debug('Removing entry ' + str(key) + ' from database')
        (interface_osname, protocol, udn) = key
        if protocol is not None:	# Protocol may not be provided, in that case, we consider it a wildcard (remove all protocols)
            if key in self._database.keys():
                del self._database[key]
        else:	# Protocol is none, remove all entries matching this interface and udn
            #print('Using delete with wildcard on protocol')
            for db_key in self._database.keys():
                (db_interface_osname, db_protocol, db_udn) = db_key
                if db_interface_osname == interface_osname and db_udn == udn:	# Both interface_osname and udn match
                    logger.debug('Deleting key (' + str(db_interface_osname) + ', *=' + str(db_protocol) + ', ' + str(db_udn) + ') from database using wildcard for protocol')
                    del self._database[db_key]
    
    def reset(self):
        """\brief Empty the database"""
        self._database = {}
    
    def processEvent(self, upnp_event):
        """\brief Update this database according to the \p upnp_event
        
        \param upnp_event The event to process, provided as an instance of UpnpBrowseDeviceEvent
        """
        
        presentation_url = upnp_event.presentation_url
        
        if presentation_url is not None:
            (purl_proto, purl_hostname, purl_port, purl_path) = UpnpDeviceDatabase._upnp_purl_to_details(presentation_url)
            
            ip_version = guess_ip_version(purl_hostname)
            if ip_version == 4:
                protocol = 'ipv4'
            elif ip_version == 6:
                protocol = 'ipv6'
            else:
                protocol = None
        else:
            protocol = None	# No presentation URL... cannot guess protocol, set it to unknown
        
        key = (upnp_event.interface, protocol, upnp_event.udn)
        
        if upnp_event.event == 'add':
            upnp_device = UpnpDevice(purl_hostname,
                                     UpnpDeviceDatabase._hostname_to_ip_address(ip_version, purl_hostname),
                                     purl_port,
                                     upnp_event.device_type,
                                     upnp_event.friendly_name,
                                     upnp_event.location,
                                     upnp_event.manufacturer,
                                     upnp_event.manufacturer_url,
                                     upnp_event.model_description,
                                     upnp_event.model_name,
                                     upnp_event.model_number,
                                     upnp_event.model_url,
                                     presentation_url,
                                     upnp_event.serial_number,
                                     mac_address = None)
            #logger.debug('Will process add event on device ' + str(upnp_device))
            self.add(key, upnp_device)
        elif upnp_event.event == 'del':
            # With del events, we only use the key to delete the service (other info is not needed)
            self.remove(key)
        else:
            raise Exception('UnknownEvent')


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
         
        \return A list of tuples containing (interface, protocol, udn, hostname, ip_address, port, device_type, friendly_name, location, manufacturer, manufacturer_url, model_description, model_name, model_number, model_url, presentation_url, serial_number, mac_address)
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
                ip_address = upnp_device.ip_address
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
                export += [(interface_osname, protocol, udn, hostname, ip_address, port, device_type, friendly_name, location, manufacturer, manufacturer_url, model_description, model_name, model_number, model_url, presentation_url, serial_number, mac_address)]
         
        return export
         
    def import_from_tuple(self, tuple):
        """\brief Import a record into this database from a tuples
         
        \param tuple A tuple containing (interface, protocol, udn, hostname, ip_address, port, device_type, friendly_name, location, manufacturer, manufacturer_url, model_description, model_name, model_number, model_url, presentation_url, serial_number, mac_address), as exported into a list using export_to_tuple_list() for example 
        """
        (interface_osname, protocol, udn, hostname, ip_address, port, device_type, friendly_name, location, manufacturer, manufacturer_url, model_description, model_name, model_number, model_url, presentation_url, serial_number, mac_address) = tuple
        key = (interface_osname, protocol, udn)
        upnp_device = UpnpDevice(hostname, ip_address, port, device_type, friendly_name, location, manufacturer, manufacturer_url, model_description, model_name, model_number, model_url, presentation_url, serial_number, mac_address)
        self.add(key, upnp_device)
    
    def is_ip_address_in_db(self, ip_address):
        try:
            records = self._database.iteritems()
        except AttributeError:
            records = self._database.items()
         
        for (key, upnp_device) in records:
            if not upnp_device is None:
                if upnp_device.ip_address == ip_address:
                    return True
        return False
 
    def is_mac_address_in_db(self, mac_address):
        if mac_address is None:
            return False
         
        try:
            records = self._database.iteritems()
        except AttributeError:
            records = self._database.items()
         
        for (key, upnp_device) in records:
            if not upnp_device is None:
                if upnp_device.mac_address == mac_address:
                    return True
        return False
         
    def get_ip_address_from_mac_address(self, searched_mac, ip_type = 'all'):
        """\brief Check the IP address of a UPnP device, given its MAC address
         
        Note: the database must have been filled with a list of devices prior to calling this method
        An exception will be raised if there are two different matches in the db... None will be returned if there is no match
         
        \param searched_mac The MAC address of the device to search
        \param ip_type The version of IP searched ('ipv4', 'ipv6' or 'all' (default)
         
        \return The IP address of the device (if found)
        """
 
        searched_mac = mac_normalise(searched_mac, False)
        match = None
         
        for key in self._database.keys():
            protocol = key[1]
            if ip_type == 'all' or protocol == ip_type:
                upnp_device = self._database[key]
                if not upnp_device is None:
                    mac_product = upnp_device.mac_address
                    if not mac_product is None:
                        mac_product = mac_normalise(mac_product, False)
                        if searched_mac == mac_product:
                            ip_address = self._database[key].ip_address
                            if match is None:
                                match = ip_address
                            elif match == ip_address: # Error... there are two matching entries, with different IP addresses!
                                raise Exception('DuplicateMACAddress')
        return match
 
    def get_ip_address_from_name(self, searched_name, ip_type = 'all'):
        """\brief Check the IP address of a UPnP device, given its published name
         
        Note: the database must have been filled with a list of devices prior to calling this method
        An exception will be raised if there are two different matches in the db... None will be returned if there is no match
         
        \param searched_name The MAC address of the device to search
        \param ip_type The version of IP searched ('ipv4', 'ipv6' or 'all' (default)
         
        \return The IP address of the device (if found)
        """
 
        match = None
        #logger.debug('Searching for service "' + searched_name + '" to get its device IP type: ' + ip_type)
        for key in self._database.keys():
            protocol = key[1]
            if ip_type == 'all' or protocol == ip_type:
                upnp_device = self._database[key]
                if not upnp_device is None:
                    service_name_product = upnp_device.friendly_name
                    if service_name_product == searched_name:
                        ip_address = upnp_device.ip_address
                        if match is None:
                            match = ip_address
                        elif match == ip_address: # Error... there are two matching entries, with different IP addresses!
                            raise Exception('DuplicateServiceName')
        return match
    
    def service_available(self, *kwargs):
        print('Entering service_available() with args: ' + str(kwargs))
    
    def service_unavailable(self, *kwargs):
        print('Entering service_unavailable() with args: ' + str(kwargs))

class UpnpLibrary:
    """Robot Framework UPnP Library"""

    ROBOT_LIBRARY_DOC_FORMAT = 'ROBOT'
    ROBOT_LIBRARY_SCOPE = 'GLOBAL'
    ROBOT_LIBRARY_VERSION = '1.0'
    UPNP_BROWSER_DEFAULT_EXEC = 'scripts/UpnpBrowser.py'

    def __init__(self, upnp_browser_exec_path=None, use_sudo_for_arping=True):
        self._service_database = None
        self._service_database_mutex = threading.Lock()    # This mutex protects writes to the _service_database attribute
        if upnp_browser_exec_path is None:
            self._upnp_browser_exec_path = UpnpLibrary.UPNP_BROWSER_DEFAULT_EXEC
        else:
            self._upnp_browser_exec_path = upnp_browser_exec_path
        self._use_sudo_for_arping = use_sudo_for_arping
        self._added_device_event = threading.Event()    # New device added event (an event watcher like self._set_events_on_device_event() needs to be called in order for this flag to be representative)
        self._removed_device_event = threading.Event()    # New device remove event (same note as above)

    def _parse_upnp_browse_output(self, upnp_browse_process, interface_name_filter = None, ip_type_filter = None, event_callback = None):
        """Parse the output of an existing upnp-browse command and update self._service_database accordingly until the subprocess terminates
        \param upnp_browse_process A subprocess.Popen object for which we will process the output
        \param interface_name_filter If not None, we will only process services on this interface name
        \param ip_type_filter If not None, we will only process services with this IP type
        \param event_callback If not None, we will call this function for each database update, giving it the new UpnpBrowseDeviceEvent as argument
        """
        previous_line_continued = False
        upnp_event = None
        #print('Going to parse output of process PID ' + str(upnp_browse_process.pid))
        # We cannot use stdout iterator as usual here, because it adds some buffering on the subprocess stdout that will not provide us the output lines in real-time
        line = upnp_browse_process.stdout.readline()
        while line:
            line = line.rstrip('\n')
            #print('upnp-browse:"' + line + '"')
            if previous_line_continued:
                upnp_event.add_line(line)
            else:
                upnp_event = UpnpBrowseDeviceEvent(line.split(';'))
            previous_line_continued = upnp_event.continued_on_next_line()
            if not previous_line_continued:
                #~ print('Getting event ' + str(upnp_event))
                if interface_name_filter is None or upnp_event.interface == interface_name_filter:   # Only take into account services on the requested interface (if an interface was provided)
                    if ip_type_filter is None or upnp_event.ip_type == ip_type_filter:   # Only take into account services running on the requested IP stack (if an IP version was provided)
                        with self._service_database_mutex:
                            self._service_database.processEvent(upnp_event)
                        if not event_callback is None and hasattr(event_callback, '__call__'):
                            event_callback(upnp_event) # If there is a callback to trigger when an event is processed, also run the callback
            line = upnp_browse_process.stdout.readline()

    def _set_internal_events_on_new_device_event(self, event):
        """Set threading.Event flags when a new device event is received
        
        This function will set self._added_device_event when \p event corresponds to an added device event and will set self._removed_device_event when \p event corresponds to an removed device event
        It is aimed to be provided as a callback (argument event_callback) to _parse_upnp_browse_output
        
        \param event The new event received
        """
        if event.event == 'add':
            #logger.debug('Got add event... setting self._added_device_event')
            self._added_device_event.set()
        elif event.event == 'del':
            #logger.debug('Got add event... setting self._removed_device_event')
            self._removed_device_event.set()
            
    def _kill_process_at_timeout(self, process, threading_event, timeout, disable_event = None):
        """Kill a UpnpBrowse.py subprocess when a threading event has not been set for longer than \p timeout
        
        At each new triggering event, we will clear again threading_event... and wait for \p timeout seconds on it to be set again... if it is not set after this timeout, we will send a SIGKILL to \p process (a subprocess.Popen object)
        This function should be run in a secondary thread and acts as a watchdog
        
        \param process The subprocess.Popen object to send a kill signal to
        \param threading_event The threading.Event to watch
        \param timeout The timeout after which we will kill the subprocess if \p threading_event has not been set()
        \param stop_event An optional threading.Event used to disable this function (if it is set when the timeout occurs, we will exit without sending the kill signal)
        """
        while threading_event.wait(timeout):
            #logger.debug('Watchdog reset for ' + str(timeout) + 's')
            threading_event.clear() # Reset the event and wait again
        #logger.debug('Watchdog trigerred')
        if not disable_event is None:
            if disable_event.is_set():
                return
        logger.info('Killing subprocess ' + str(process.pid))
        process.kill()
         
        
    def get_services(self, device_type = 'upnp:rootdevice', interface_name = None, ip_type = None, resolve_ip = True, timeout = 2):
        """Get all currently published UPnP services as a list
        
        First (optional) argument `device_type` is the type of service (in the GUPnP terminology, the default value being `upnp:rootdevice`)
        Second (optional) argument `interface_name` is the name of the network interface on which to browse for UPnP devices (if not specified, search will be performed on all valid network interfaces)
        Third (optional) argument `ip_type` is the type of IP protocol to filter our (eg: `ipv6`, or `ipv4`, the default values being any IP version)
        Fourth (optional) argument `resolve_ip`, when True, will also include the MAC address of devices in results (default value is to resolve IP addresses)
        Fifth (optional) argument `timeout`, is the timeout we will wait after each newly discovered device before considering we have finished the network discovery (increase this on slow networks)
        
        Return a list of services found on the network (one entry per service, each service being described by a tuple containing (interface_osname, protocol, udn, hostname, ip_address, port, device_type, friendly_name, location, manufacturer, manufacturer_url, model_description, model_name, model_number, model_url, presentation_url, serial_number, mac_address) = tuple
        The return value can be stored and re-used later on to rework on this service list (see keyword `Import Results`) 
        
        Example:
        | @{result_list} = | Get Services | upnp:rootdevice |
        
        | @{result_list} = | Get Services | upnp:rootdevice | eth1 |
        
        | @{result_list} = | Get Services | upnp:rootdevice | eth1 | ipv6 |
        """
        
        if interface_name is None:
            logger.warn('Browsing on all interfaces is not supported in UpnpLibrary')
            raise Exception('NotSupported')
        
        with self._service_database_mutex:
            self._service_database = UpnpDeviceDatabase(resolve_mac = resolve_ip, use_sudo_for_arping = self._use_sudo_for_arping)
        
        if device_type and device_type != '*':
            device_type_arg = ['-T', device_type]
        else:
            device_type_arg = []

        self._added_device_event.clear()    # Clear _added_device_event to start watching for newly discovered devices
        cmd = [self._upnp_browser_exec_path, '-i', interface_name] + device_type_arg
        logger.debug('Now running subscript ' + str(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        _added_device_timeout_handler = threading.Thread(target = self._kill_process_at_timeout, args=(p, self._added_device_event, timeout))    # Start a background thread that will stop the subprovess when no new discovery occurs within a specified timeout
        _added_device_timeout_handler.setDaemon(True)    # D-Bus loop should be forced to terminate when main program exits
        _added_device_timeout_handler.start()
        
        self._parse_upnp_browse_output(upnp_browse_process=p, interface_name_filter=interface_name, ip_type_filter=ip_type, event_callback=self._set_internal_events_on_new_device_event)   # We use self._set_internal_events_on_new_device_event() as callback so that it will set _added_device_event to reset the watchdog handled by thread _added_device_timeout_handler
        
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

    def get_service_on_ip(self, ip_address):
        """Reduce the current server database for only services matching with the provided IP address
        
        Note: `Get Services` or `Import Results` must have been run prior to calling this keyword
        To make sure you restrict to IPv4 or IPv6, filter IP types when running `Get Services`
        
        Note: running this keyword will have the effect of changing the current database results from `Get Services` (used by other keywords)
        
        Example:
        | Get Services | upnp:rootdevice | eth1 | ipv4 |
        | @{result_list} = | Get Service On IP | 192.168.0.1 |
        """

        with self._service_database_mutex:
            self._service_database.keep_only_ip_address(ip_address)
            return self._service_database.export_to_tuple_list()
            
    def get_service_on_mac(self, mac_address):
        """Reduce the current server database for only services matching with the provided MAC address
        
        Note: `Get Services` or `Import Results` must have been run prior to calling this keyword
        
        Note: running this keyword will have the effect of changing the current database results from `Get Services` (used by other keywords)
        
        In order to use this keyword, you will need to request IP to MAC address resolution (4th argument of Get Services)
        
        Example:
        | Get Services | upnp:rootdevice | eth1 | ipv4 |
        | @{result_list} = | Get Service On MAC | 00:04:74:02:26:47 |
        """

        with self._service_database_mutex:
            self._service_database.keep_only_mac_address(mac_address)
            return self._service_database.export_to_tuple_list()

    def expect_service_on_ip(self, ip_address):
        """Test if a service has been listed on device with IP address `ip_address`
        
        Note: `Get Services` or `Import Results` must have been run prior to calling this keyword
        To make sure you restrict to IPv4 or IPv6, filter IP types when running `Get Services`
        
        Example:
        | Expect Service On IP | 192.168.0.1 |
        """

        with self._service_database_mutex:
            if not self._service_database.is_ip_address_in_db(ip_address):
                raise Exception('ServiceNotFoundOn:' + str(ip_address))

    def expect_no_service_on_ip(self, ip_address):
        """Test if a service is absent from device with IP address `ip_address`
        
        Note: `Get Services` or `Import Results` must have been run prior to calling this keyword
        To make sure you restrict to IPv4 or IPv6, filter IP types when running `Get Services`
        
        Example:
        | Expect No Service On IP | 192.168.0.1 |
        """

        with self._service_database_mutex:
            if self._service_database.is_ip_address_in_db(ip_address):
                raise Exception('ServiceExistsOn:' + str(ip_address))
    
    def expect_service_on_mac(self, mac_address):
        """Test if a service has been listed on device with MAC address `mac_address`
        
        Note: `Get Services` or `Import Results` must have been run prior to calling this keyword
        
        In order to use this keyword, you will need to request IP to MAC address resolution (4th argument of Get Services)
        
        Example:
        | Expect Service On MAC | 00:04:74:05:38:38 |
        """

        with self._service_database_mutex:
            if not self._service_database.is_mac_address_in_db(mac_address):
                raise Exception('ServiceNotFoundOn:' + str(mac_address))

    def expect_no_service_on_mac(self, mac_address):
        """Test if a service is absent from device with MAC address `mac_address`
        
        Note: `Get Services` or `Import Results` must have been run prior to calling this keyword
        
        In order to use this keyword, you will need to request IP to MAC address resolution (4th argument of Get Services)
        
        Example:
        | Expect No Service On MAC | 00:04:74:05:38:38 |
        """

        with self._service_database_mutex:
            if self._service_database.is_mac_address_in_db(mac_address):
                raise Exception('ServiceExistsOn:' + str(mac_address))
            
    def get_ipv4_for_mac(self, mac):
        """Returns the IPv4 address matching MAC address from the list a Bonjour devices in the database
        
        Note: The search will be performed on the service cache so `Get Services` or `Import Results` must have been run prior to calling this keyword
        If there is more than one IPv4 address matching with the MAC address, an exception will be raised (unlikely except if there is an IP address update in the middle of `Get Services`)
        
        In order to use this keyword, you will need to request IP to MAC address resolution (4th argument of Get Services)
        
        Return the IPv4 address or None if the MAC address was not found.
        
        Example:
        | Get IPv4 For MAC | 00:04:74:12:00:01 |
        =>
        | 169.254.47.26 |
        """

        with self._service_database_mutex:
            return self._service_database.get_ip_address_from_mac_address(mac, ip_type='ipv4')

    def get_ipv6_for_mac(self, mac):
        """Returns the IPv6 address matching MAC address mac from the list a Bonjour devices in the database
        
        Note: The search will be performed on the service cache so `Get Services` or `Import Results` must have been run prior to calling this keyword
        If there is more than one IPv4 address matching with the MAC address, an exception will be raised (unlikely except if there is an IP address update in the middle of `Get Services`)
        
        In order to use this keyword, you will need to request IP to MAC address resolution (4th argument of Get Services)
        
        Return the IPv6 address or None if the service was not found.
        
        Example:
        | Get IPv6 For MAC | 00:04:74:12:00:01 |
        =>
        | fe80::204:74ff:fe12:1 |
        """

        with self._service_database_mutex:
            return self._service_database.get_ip_address_from_mac_address(mac, ip_type='ipv6')

    def get_ipv4_for_device_name(self, device_name):
        """Get the IPv4 address for the device named `device_name`.
        
        Note: The search will be performed on the service cache so `Get Services` or `Import Results` must be called before calling this keyword
        
        Return the IPv4 address or None if the service was not found.
        If more than one service matches \p device_name, an exception will be raised
        
        Example:
        | ${ip} = | Get IPv4 For Device Name | Workstation000474 |
        =>
        | 169.254.4.74 |
        """

        with self._service_database_mutex:
            return self._service_database.get_ip_address_from_name(device_name, ip_type='ipv4')

    def get_ipv6_for_device_name(self, device_name):
        """Get the IPv6 address for the device named `device_name`.
        
        Note: The search will be performed on the service cache so `Get Services` or `Import Results` must be called before calling this keyword
        
        Return the IPv6 address or None if the service was not found.
        If more than one service matches \p device_name, an exception will be raised
        
        Example:
        | ${ip} = | Get IPv6 For Device Name | Workstation000474 |
        =>
        | fe80::1 |
        """

        with self._service_database_mutex:
            return self._service_database.get_ip_address_from_name(device_name, ip_type='ipv6')
    
    def import_results(self, result_list):
        """Import a service result list (previously returned by `Get Services` in order to work again/filter/extract from that list
        
        Will raise an exception of the list is not correctly formatted
        
        Example:
        | Import Results | @{result_list} |
        """
        
        logger.info('Manually importing the following results into the database:' + str(result_list))
        with self._service_database_mutex:
            self._service_database.reset()
            for service in result_list:
                self._service_database.import_from_tuple(service)


if __name__ == '__main__':
    try:
        input = raw_input
    except NameError:
        pass

    host = 'hal2'
    if host=='hal':
        IP = '169.254.2.35'
        MAC = '00:04:74:12:00:00'
        exp_device = 'Wifi_wifi-soho_120000'
    elif host=='hal2':
        IP = '10.10.8.31'
        MAC = '00:04:74:05:00:BA'
        exp_device = 'LegrandAP_AP Wifi_0500BA'
    
    #print('Arping result: ' + str(arping(ip_address='10.10.8.1', interface='eth0', use_sudo=True, logger=logger)))
    UPNP_BROWSER = 'scripts/UpnpBrowser.py'
    UL = UpnpLibrary()
    input('Press enter & "Enable UPnP" on device')
    temp_cache = UL.get_services(interface_name='eth0')
    print('For device ' + exp_device + ', got IP ' + UL.get_ipv4_for_device_name(exp_device))
    if IP != UL.get_ipv4_for_device_name(exp_device):
        raise Exception('Error')
    print('For MAC ' + MAC + ', got IP ' + UL.get_ipv4_for_mac(MAC))
    if IP != UL.get_ipv4_for_mac(MAC):
        raise Exception('Error')
    #if 'fe80::21a:64ff:fe94:86a2' != UL.get_ipv6_for_mac(MAC):
    #    raise Exception('Error')
    UL.expect_service_on_ip(IP)
    UL.expect_service_on_mac(MAC)
    UL.import_results([])  # Make sure we reset the internal DB
    UL.expect_no_service_on_ip(IP)  # So there should be no service of course!
    UL.import_results(temp_cache)  # Re-import previous results
    UL.expect_service_on_ip(IP)  # We should get again the service that we found above
    #input('Press enter & publish a device called "' + exp_device + '" within 10s')
    #UL.wait_for_device_name(exp_device, timeout=10, interface_name='eth1')
    input('Press enter & either Disable UPnP on device or stop publishing device called "' + exp_device + '" within 20s')
    #UL.wait_for_no_device_name(exp_device, timeout=20, interface_name='eth1')
    UL.get_services(interface_name='eth0')
    UL.expect_no_service_on_ip(IP)
    UL.expect_no_service_on_mac(MAC)
