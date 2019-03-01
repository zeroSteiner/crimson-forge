#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  crimson_forge/catalog.py
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the  nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import argparse
import binascii
import bz2
import datetime
import distutils.version
import hashlib
import json
import logging
import lzma
import os
import sys

import crimson_forge.utilities

import lief

logger = logging.getLogger('crimson-forge.catalog')

data_directory = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data'))

schema_version = '1.0'

# https://www.alvestrand.no/objectid/2.5.4.html
_OIDS = {
	'2.5.4.3': 'common-name',
	'2.5.4.6': 'country-name',
	'2.5.4.7': 'locality-name',
	'2.5.4.8': 'state-or-province-name',
	'2.5.4.10': 'organization-name'
}

def _b2a_base64(data):
	return binascii.b2a_base64(data).decode('utf-8').rstrip()

def _binary_data(data, key: str):
	data = lzma.compress(data)
	data = _b2a_base64(data)
	return {key: data, key +':encoding': 'base64', key + ':compression': 'lzma'}

def _load_catalog(catalog_path):
	with open(catalog_path, 'r') as file_h:
		catalog = json.load(file_h)
	version = catalog.get('schema-version', '0.0')
	compatible = True
	if distutils.version.StrictVersion(version) < distutils.version.StrictVersion(schema_version):
		compatible = False
	else:
		major, minor = schema_version.split('.')
		next_schema_version = str(int(major) + 1) + '.' + minor
		if distutils.version.StrictVersion(version) >= distutils.version.StrictVersion(next_schema_version):
			compatible = False
	return catalog, compatible

def _process_entry(entry: dict, recursive: bool=True) -> dict:
	if not isinstance(entry, dict):
		raise TypeError('entry must be a dictionary')
	processed_entry = dict((k, v) for (k, v) in entry.items() if ':' not in k)
	for key, value in processed_entry.items():
		encoding = entry.get(key + ':encoding', '').lower()
		if encoding == 'base64':
			value = binascii.a2b_base64(value)
		elif encoding == 'hex':
			value = binascii.a2b_hex(value)
		elif encoding:
			raise ValueError("Unsupported encoding setting {!r} for {}".format(encoding, key))

		compression = entry.get(key + ':compression', '').lower()
		if compression == 'bzip2':
			value = bz2.decompress(value)
		elif compression == 'lzma':
			value = lzma.decompress(value)
		elif compression:
			raise ValueError("Unsupported compression setting {!r} for {}".format(encoding, key))
		if recursive and isinstance(value, dict):
			value = _process_entry(value, recursive=recursive)
		processed_entry[key] = value
	return processed_entry

def get_entry_group(name, required_keys=None):
	catalog, compatible = _load_catalog(os.path.join(data_directory, 'catalog.json'))
	if not compatible:
		raise RuntimeError('incompatible catalog schema version')
	entry_group = catalog[name]
	if not isinstance(entry_group, (dict, list)):
		raise TypeError('selected catalog entry is not a dictionary or list')

	# if a local catalog exists, load it and have it's entry take priority
	if os.path.isfile(os.path.join(data_directory, 'catalog.local')):
		catalog, compatible = _load_catalog(os.path.join(data_directory, 'catalog.local.json'))
		if compatible:
			if isinstance(entry_group, dict):
				local_entry_group = catalog.get(name, {})
				entry_group.update(local_entry_group)
			elif isinstance(entry_group, list):
				local_entry_group = catalog.get(name, [])
				local_entry_group.extend(entry_group)
				entry_group = local_entry_group

	processed_entry_group = []
	for entry in entry_group:
		if required_keys and not all(key in entry for key in required_keys):
			continue
		processed_entry_group.append(_process_entry(entry))
	return processed_entry_group

def store_catalog(path, catalog):
	with open(path, 'w') as file_h:
		json.dump(catalog, file_h, indent=2, separators=(',', ': '), sort_keys=True)

def main():
	parser = argparse.ArgumentParser(description='Catalog Updater', conflict_handler='resolve')
	parser.add_argument('binary', help='The binary to update the catalog with')
	parser.add_argument('-c', '--catalog', dest='catalog', default=os.path.join(data_directory, 'catalog.local.json'), help='The catalog to update')
	args = parser.parse_args()

	if not os.access(args.binary, os.R_OK) and os.path.isfile(args.binary):
		crimson_forge.utilities.print_error('The specified binary is not a readable file')
		return os.EX_USAGE
	timestamp = datetime.datetime.utcnow().isoformat() + '+00:00'
	binary = lief.parse(args.binary)
	if not isinstance(binary, lief.PE.Binary):
		crimson_forge.utilities.print_error('Only Portable Executable (PE) binaries are supported')
		return os.EX_DATAERR
	if lief.PE.HEADER_CHARACTERISTICS.EXECUTABLE_IMAGE not in binary.header.characteristics_list:
		crimson_forge.utilities.print_error('Only executable PE binaries are supported')
		return os.EX_DATAERR

	if os.path.isfile(args.catalog):
		if not os.access(args.catalog, os.R_OK | os.W_OK):
			crimson_forge.utilities.print_error('Can not read and write to the specified catalog file')
			return os.EX_NOPERM
		catalog, compatible = _load_catalog(args.catalog)
		if not compatible:
			crimson_forge.utilities.print_error('The specified catalog is not compatible')
	else:
		catalog = {'binaries': [], 'created-at': timestamp, 'schema-version': schema_version}

	file_h = open(args.binary, 'rb')
	binary_hash = _b2a_base64(hashlib.new('sha256', file_h.read()).digest())
	for entry in catalog['binaries']:
		if entry['hash-sha256'] == binary_hash:
			crimson_forge.utilities.print_status('This binary is already in the catalog, no further processing is necessary')
			file_h.close()
			return os.EX_OK

	entry = {
		'created-at': timestamp,
		'file-name': os.path.basename(args.binary),
		'hash-sha256': binary_hash,
		'hash-sha256:encoding': 'base64',
		'type': ('pe:exe:dll' if lief.PE.HEADER_CHARACTERISTICS.DLL in binary.header.characteristics_list else 'pe:exe')
	}

	if binary.signature:
		directory = binary.data_directories[lief.PE.DATA_DIRECTORY.CERTIFICATE_TABLE]
		file_h.seek(directory.rva)
		data = file_h.read(directory.size)
		signature = _binary_data(data, 'data')
		issuer = {}
		for values in binary.signature.signer_info.issuer[0]:
			if len(values) != 2:
				continue
			oid, value = values
			oid_name = _OIDS.get(oid)
			if oid_name:
				issuer[oid_name] = value
		if issuer:
			signature['issuer'] = issuer
		entry['authenticode-signature'] = signature

	file_h.close()
	catalog['binaries'].append(entry)
	catalog['modified-at'] = timestamp
	store_catalog(args.catalog, catalog)

if __name__ == '__main__':
	sys.exit(main())
