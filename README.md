UpnpLibrary for Robot Framework
==================================


## Introduction

UpnpLibrary is a [Robot Framework](http://robotframework.org) test
library for testing devices announcing services using the UPnP/SSDP protocol.
It will browse the UPnP devices on the network and allow Robot Framework to
use all information provided by the UPnP/SSDP protocol via Robot Framework
keywords.

By default, this library resolves IP addresses to MAC addresses. For this, it
also requires the arping utility (and will most often also require sudo
privileges to run arping under Linux)

BonjourLibrary is open source software licensed under
[Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0.html).

## For users

### Prerequisites

This library requires the following executables to be accessible:
- arping (if IP to MAC address is required)

### Installation

To install this libary, run the `./setup.py install` command locate inside the
repository.

### Robot Framework keywords

The following RobotFramework keywords are made available by this library:
Note: it is advised to go directly inside the python code's docstrings (or via
RIDE's online help) to get a detailed description of keywords).

#### `Get Devices`

*Retrieve the list of UPnP devices*

The first (optional) argument is the type of device (in the UPnP terminology, the default value being `BasicDevice`)
The second (optional) argument is the name of the network interface on which to browse for UPnP devices (if not specified, search will be performed on all valid network interfaces)
The third (optional) argument is the type of IP protocol to filter our (eg: `ipv6`, or `ipv4`, the default values being any IP version)
If the fourth (optional) argument is set to True, we will also include the MAC address of devices in results (default value is to resolve IP addresses)

Return a list of dervices found on the network
Each entry of the list will contain a tuple describing a dervice. The tuple's element are (in order).

* interface: The network interface on which the service has been discovered
  (following the OS notation, eg: 'eth0')
* protocol: The type of IP protocol on which the service is published ('ipv4'
  or 'ipv6')
* name: The human-friendy name of the service as displayed by Bonjour browsing
  utilities
* stype: The service type following Bonjour's convention, eg '_http._tcp'
* domain: The domain on which the service was discovered, eg 'local'
* hostname: The hostname of the device publishing the service (eg: blabla.local)
* ip_address The IP address of the device publishing the service (eg:
  '192.168.0.1' or 'fe80::1')
* port: The TCP or UDP port on which the service is running (eg: 80)
* txt: The TXT field associated with the service

### Robot Framework future keywords?

This lists keywords that might be implemented in the future if required:

