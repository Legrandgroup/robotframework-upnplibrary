#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function

import os
import sys
import itertools
import threading

import logging
import argparse

from gi.repository import GLib, GUPnP
from gi.repository import GSSDP

progname = os.path.basename(sys.argv[0])

VERSION = '1.0.0'

class UpnpDeviceWatcher():
	"""UPnP device browser"""
	
	def __init__(self, interface, db_add_event = None, db_del_event = None):
		"""Initialise a UPnP Device watcher on interface \p interface
		
		\param interface The network interface on which devices are discovered
		\param db_add_event If not None, we will invoke this threading.Event()'s set() method for every device added to the database
		\param db_del_event If not None, we will invoke this threading.Event()'s set() method for every device removed from the database
		"""
		self.interface = interface
		self._db_add_event = db_add_event
		self._db_del_event = db_del_event
	
	@staticmethod
	def escape_string(input):
		"""\brief Escape special characters in string \p input
		
		\param input String to escape
		
		\return The escaped string (we will mainly escape control characters <32 (incluing carriage return, line feed), non-printable ones >=127 and backslashes and semi-colons)
		"""
		output = ''
		#logger.debug('Escaping string "' + str(input) + '"')
		while input:
			try:
				pos = (index for ch, index in itertools.izip(input, itertools.count()) if (ord(ch)<32 or ord(ch)>=127 or ch=='\\' or ch==';')).next()
				#logger.debug('Found character \'' + input[pos] + '\' to escape at index ' + str(pos))
				output += input[:pos] + '\\' + str(ord(input[pos])).zfill(3)
				input = input[pos+1:]	# Remove all previous characters including the escaped one
			except StopIteration:	# No character to escape, just copy
				output += input
				input=''
		return output
	
	def device_available(self, cp, proxy):
		"""Callback run when a new UPnP device is discovered
		
		\param cp A GUPnP.ControlPoint object that caught the new device event
		\param proxy An instance of GUPnP.DeviceProxy to get information about this device
		"""
		# See http://lazka.github.io/pgi-docs/#GUPnP-1.0/classes/DeviceInfo.html#gupnp-deviceinfo-methods
		#print('Entering device_available() with args: [' + str(cp) + ' ,' + str(proxy) + ']')
		if self._db_add_event is not None:
			self._db_add_event.set()
		output = '+;'
		device_type = proxy.get_device_type()
		friendly_name = proxy.get_friendly_name()
		location = proxy.get_location()
		manufacturer = proxy.get_manufacturer()
		manufacturer_url = proxy.get_manufacturer_url()
		model_description = proxy.get_model_description()
		model_name = proxy.get_model_name()
		model_number = proxy.get_model_number()
		model_url = proxy.get_model_url()
		presentation_url = proxy.get_presentation_url()
		serial_number = proxy.get_serial_number()
		udn = proxy.get_udn()
		
		output += self.escape_string(self.interface) + ';'
		output += self.escape_string(udn) + ';'
		
		if device_type is None:
			device_type=''
		else:
			device_type=str(device_type)
		output += self.escape_string(device_type) + ';'
		
		if friendly_name is None:
			friendly_name=''
		else:
			friendly_name=str(friendly_name)
		output += self.escape_string(friendly_name) + ';'
		
		if location is None:
			location=''
		else:
			location=str(location)
		output += self.escape_string(location) + ';'
		
		if manufacturer is None:
			manufacturer=''
		else:
			manufacturer=str(manufacturer)
		output += self.escape_string(manufacturer) + ';'
		
		if manufacturer_url is None:
			manufacturer_url=''
		else:
			manufacturer_url=str(manufacturer_url)
		output += self.escape_string(manufacturer_url) + ';'
		
		if model_description is None:
			model_description=''
		else:
			model_description=str(model_description)
		output += self.escape_string(model_description) + ';'
		
		if model_name is None:
			model_name=''
		else:
			model_name=str(model_name)
		output += self.escape_string(model_name) + ';'
		
		if model_number is None:
			model_number=''
		else:
			model_number=str(model_number)
		output += self.escape_string(model_number) + ';'
		
		if model_url is None:
			model_url=''
		else:
			model_url=str(model_url)
		output += self.escape_string(model_url) + ';'
		
		if presentation_url is None:
			presentation_url=''
		else:
			presentation_url=str(presentation_url)
		output += self.escape_string(presentation_url) + ';'
		
		if serial_number is None:
			serial_number=''
		else:
			serial_number=str(serial_number)
		output += self.escape_string(serial_number)

		print(output, file=sys.stdout)
		try:
			sys.stdout.flush()	# Make sure we flush at each line
		except IOError:
			pass	# If output stream is already closed (caller has exitted, for example=, we would get an exception here... just ignore it (we have output the line anyway)
		#print('service_types: ' + str(proxy.list_service_types()))	# Should be GLib.free()'d and list should also be GLib.List.free()'d
		#print('services: ' + str(proxy.list_services()))	# Should be GLib.free()'d and list should also be GLib.List.free()'d
		
	
	def device_unavailable(self, cp, proxy):
		"""Callback run when a new UPnP device disappears
		
		\param cp A GUPnP.ControlPoint object that caught the new device event
		\param proxy An instance of GUPnP.DeviceProxy to get information about this device
		"""
		# See http://lazka.github.io/pgi-docs/#GUPnP-1.0/classes/DeviceInfo.html#gupnp-deviceinfo-methods
		#print('Entering device_unavailable() with args: [' + str(cp) + ' ,' + str(proxy) + ']')
		if self._db_del_event is not None:
			self._db_del_event.set()
		output = '-;'
		udn = str(proxy.get_udn())
		output += self.escape_string(self.interface) + ';'
		output += self.escape_string(udn)
		
		print(output, file=sys.stdout)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="This program displays the UPnP devices in the network neighborhood. \
It will report every UPnP devices that appears and disappears in real-time, and as a parsable line-by-line output.", prog=progname)
	parser.add_argument('-i', '--ifname', type=str, help='network interface on which to perform the discovery', default='eth0') #required=True)
	parser.add_argument('-t', '--dumpandexit', action='store_true', help='don\'t continue listening for changes, exit immediately after dump the current devices list', default=False)
	parser.add_argument('-T', '--devicetype', type=str, help='UPnP device type to browse', default='upnp:rootdevice')
	parser.add_argument('-s', '--timeout', type=int, help='timeout (in s) to exit if no new device has been added in -t mode', default=5)
	parser.add_argument('-d', '--debug', action='store_true', help='display debug info', default=False)
	args = parser.parse_args()

	logging.basicConfig()
	
	logger = logging.getLogger(__name__)
	
	if args.debug:
		logger.setLevel(logging.DEBUG)
	else:
		logger.setLevel(logging.INFO)
	
	handler = logging.StreamHandler()
	handler.setFormatter(logging.Formatter("%(levelname)s %(asctime)s %(module)s:%(lineno)d %(message)s"))
	logger.addHandler(handler)
	logger.propagate = False
	
	logger.debug("Starting")

	_service_database_added_event = threading.Event()	# This event is set when a device is added to the database
	_service_database_deleted_event = threading.Event()	# This event is set when a device is added to the database

	watcher = UpnpDeviceWatcher(interface=args.ifname, db_add_event=_service_database_added_event, db_del_event=_service_database_deleted_event)
		
	try:
		ctx = GUPnP.Context.new(None, args.ifname, 0)
	except TypeError:
		# Versions of gupnp older than 0.17.2 require context to be non None
		# Newer versions have deprecated use of any non-None first argument
		# See http://lazka.github.io/pgi-docs/#GUPnP-1.0/classes/Context.html#GUPnP.Context.new
		main_ctx = GLib.main_context_default() 
		ctx = GUPnP.Context.new(main_ctx, args.ifname, 0)
			

	cp = GUPnP.ControlPoint.new(ctx, args.devicetype)
	cp.set_active(True)
	id1 = cp.connect("device-proxy-available", watcher.device_available)
	id2 = cp.connect("device-proxy-unavailable", watcher.device_unavailable)
	
	logger.debug('Going to run mainloop')
	_mainloop = GLib.MainLoop()
	
	if args.dumpandexit:
		def _quit_dbus_when_discovery_done():
			"""This method will notify that we assume database construction is finished
			"""
			logger.debug('Waiting for event')
			while _service_database_added_event.wait(args.timeout):
				logger.debug('Got add event... resetting timer')
				_service_database_added_event.clear()  # Reset the flag we are watching... let the DB notify us when changes are made
				
			_mainloop.quit()
		
		_dbus_stop_loop_thread = threading.Thread(target = _quit_dbus_when_discovery_done)	# Start a background thread that will stop the mainloop below when no new discovery occurs
		_dbus_stop_loop_thread.setDaemon(True)	# D-Bus loop should be forced to terminate when main program exits
		_dbus_stop_loop_thread.start()
	
	try:
		_mainloop.run()
	except KeyboardInterrupt:
		cp.disconnect(id1)
		cp.disconnect(id2)
		cp.set_active(False)
		exit(1)
		
	logger.debug('Mainloop has terminated')
	
	cp.disconnect(id1)
	cp.disconnect(id2)
	cp.set_active(False)
	
	logger.debug('Control point is now inactive')

