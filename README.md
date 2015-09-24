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
- gupnp-gi

gupnp-gi is used so that python can use the GObject introspection to use
the [GUPnP library](https://wiki.gnome.org/Projects/GUPnP)

GUPnP is the UPnP and SSDP engine that makes the Robotframework UpnpLibrary
discover devices on the network.

In order to have gupnp-gi work on you machine,
[clone the sources of gupnp-gi](https://github.com/ZachGoldberg/gupnp-gi)

Move to the sources directory, and instal all pre-requisite build tools.

For example, on a Debian Jessie distro, I had to:
```shell
apt-get install gtk-doc-tools libgupnp-1.0-dev
```

If there are issues for glib undefined symbols, you can edit the `Makefile.am`,
remove from the `SUBDIRS` variable all striclty non-required (non-runtime)
directories:
* examples
* doc
* test

Once done, compile gupnp-gi:
```shell
./autogen.sh
./configure
make all
sudo make install
```

Now that gupnp-gi is installed, you can check that python can access it
properly by running:
```
python -c 'from gi.repository import GLib, GUPnP'
```

### Installation

To install this libary, run the `./setup.py install` command locate inside the
repository.

### Robot Framework keywords

The following RobotFramework keywords are made available by this library:
Note: it is advised to go directly inside the python code's docstrings (or via
RIDE's online help) to get a detailed description of keywords).

#### `Get Services`

*Retrieve the list of UPnP devices*

* The first (optional) argument `device_type` is the type of service (in the 
  GUPnP terminology, the default value being `upnp:rootdevice`)
* The second (optional) argument `interface_name` is the name of the network 
  interface on which to browse for UPnP devices (if not specified, search will 
  be performed on all valid network interfaces)
* The third (optional) argument `ip_type` is the type of IP protocol to filter 
  our (eg: `ipv6`, or `ipv4`, the default values being any IP version)
* The fourth (optional) argument `resolve_ip`, when True, will also include the 
  MAC address of devices in results (default value is to resolve IP addresses)
* The fifth (optional) argument `timeout`, is the timeout we will wait after 
  each newly discovered device before considering we have finished the network 
  discovery (increase this on slow networks)

Return a list of devices found on the network

Each entry of the list will contain a tuple describing a device. The tuple's 
element are (in order).

1. `interface`: The network interface on which the service has been discovered
   (following the OS notation, eg: 'eth0')
2. `protocol`: The type of IP protocol on which the service is published ('ipv4'
   or 'ipv6')
3. `udn`: The UDN of the UPnP device (unique ID)
4. `hostname`: The hostname (IP address) of the device, extracted from the
   presentation URL
5. `port`: The TCP port on which the device will provide a web interface,
   extracted from the presentation URL
6. `friendly_name`: The UPnP friendly name (displayed when browsing the network 
   neighborhood)
7. `location`: The URL of the xml device description
8. `manufacturer`: The device manufacturer (if any)
9. `manufacturer_url`: The device manufacturer's online URL (if any)
10. `model_description`: A (human readable) model description of the device (if 
    any)
11. `model_name`: The model name of the device (if any)
12. `model_number`: The model number (usually a product version, or revision) of
    the device (if any)
13. `model_url`: An URL to an online device model description (if any)
14. `presentation_url`: The URL to connect to when double-clicking on the 
    device, usually showing status or configuration webpages (if any)
15. `serial_number`: The serial number of the device, often matching with the 
    MAC address (if any)

#### `Expect Service On IP`

*Test if the specified IP address correspond to a device avertising using UPnP*

Note: the search will be performed on the service cache so `Get Services` or 
`Import Results` must have been run prior to calling this keyword

Also this means that this keyword will perform not perform the check for service
right now but rather at the time the last `Get Services` updated the internal
service cache.

To make sure you restrict to IPv4 or IPv6, filter IP types when running 
`Get Services`

#### `Expect No Service On IP`

*Test if the device with the specified IP address does not avertise using UPnP*

Note: the search will be performed on the service cache so `Get Services` or 
`Import Results` must have been run prior to calling this keyword

Also this means that this keyword will perform not perform the check for service
right now but rather at the time the last `Get Services` updated the internal
service cache.

To make sure you restrict to IPv4 or IPv6, filter IP types when running 
`Get Services`

#### `Get Service On IP`

*Filters results obtained by `Get Services` only returning entries for a 
specific IP address*

Note: this will have the side effect of changing the current database results 
from `Get Services` (used by other keywords)

#### `Get Service On MAC`

*Filters results obtained by `Get Services` only returning entries for a 
specific MAC address... will obviously have MAC resolution on results*

Note: this will have the side effect of changing the current database results 
from `Get Services` (used by other keywords)

#### `Get IPv4 For MAC`

*Returns the IPv4 address of a UPnP device matching MAC address*

Note: the search will be performed on the service cache so `Get Services` or 
`Import Results` must have been run prior to calling this keyword

Also this means that this keyword will perform not perform the check for service
right now but rather at the time the last `Get Services` updated the internal
service cache.

We can only search devices which did publish a UPnP service that was in the 
filter of a call to `Get Services`
In order to use this keyword, you will need to request IP to MAC address 
resolution (6th argument of `Get Services`)

If there is more than one IPv4 address matching with the MAC address, an 
exception will be raised (unlikely except if there is an IP address update in 
the middle of `Get Services`)

#### `Get IPv6 For MAC`

*Returns the IPv6 address of a UPnP device matching MAC address*

Note: the search will be performed on the service cache so `Get Services` or 
`Import Results` must have been run prior to calling this keyword

Also this means that this keyword will perform not perform the check for service
right now but rather at the time the last `Get Services` updated the internal
service cache.

We can only search devices which did publish a UPnP service that was in the 
filter of a call to `Get Services`
In order to use this keyword, you will need to request IP to MAC address 
resolution (6th argument of `Get Services`)

If there is more than one IPv6 address matching with the MAC address, an 
exception will be raised (unlikely except if there is an IP address update in 
the middle of `Get Services`)

#### `Get IPv4 For Device Name`

*Get the IPv4 address for the device publishing under a given UPnP device
friendly name*

Note: the search will be performed on the service cache so `Get Services` or 
`Import Results` must have been run prior to calling this keyword

Also this means that this keyword will perform not perform the check for service
right now but rather at the time the last `Get Services` updated the internal
service cache.

Return the IPv4 address or None if the service was not found.

If more than one service matches the requested service name, an exception will 
be raised

#### `Get IPv6 For Service Name`

*Get the IPv6 address for the device publishing under a given UPnP device
friendly name*

Note: the search will be performed on the service cache so `Get Services` or 
`Import Results` must have been run prior to calling this keyword

Also this means that this keyword will perform not perform the check for service
right now but rather at the time the last `Get Services` updated the internal
service cache.

Return the IPv6 address or None if the service was not found.

If more than one service matches the requested service name, an exception will 
be raised

#### `Import Results`

*Import a service result list (previously returned by `Get Services` in order 
to work again/filter/extract from that list*

Will raise an exception of the list is not correctly formatted

### Robot Framework future keywords?

This lists keywords that might be implemented in the future if required:

#### `Wait For Device Name`

*Wait (until a timeout) for a device to adverstise using UPnP (selection by
friendly name)*

#### `Wait For No Device Name`

*Wait (until a timeout) for a service to stop adverstising using UPnP (selection
by friendly name)*

