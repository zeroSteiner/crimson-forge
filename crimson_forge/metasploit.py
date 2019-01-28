#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  crimson_forge/metasploit.py
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

import binascii
import collections
import functools
import logging
import os

import crimson_forge.cli as cli
import metasploit.module as module

_printer = collections.namedtuple('_Printer', ('print_error', 'print_good', 'print_status', 'print_warning'))
printer = _printer(
	print_error=functools.partial(module.log, level='error'),
	print_good=functools.partial(module.log, level='good'),
	print_status=functools.partial(module.log, level='status'),
	print_warning=functools.partial(module.log, level='warning'),
)

targets = {
	'Windows x86': {
		'arch': 'x86',
		'platform': 'win',
		'options': ['--arch', 'x86'],
	},
	'Windows x64': {
		'arch': 'x64',
		'platform': 'win',
		'options': ['--arch', 'amd64'],
	},
}

metadata = {
	'name': 'Crimson Forge',
	'description': '''
		Use Crimson Forge to process a payload from the Metasploit Framework.
	 ''',
	'authors': ['Spencer McIntyre'],
	'license': 'MSF_LICENSE',
	'type': 'evasion',
	'options': {
		'LOG_LEVEL': {
			'type': 'enum',
			'description': 'The log level',
			'required': True,
			'default': 'WARNING',
			'values': ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
		},
		'LOG_NAME': {
			'type': 'string',
			'description': 'The name of the root logger',
			'required': True,
			'default': 'crimson-forge'
		},
	},
	'targets': [dict(name=name, **value) for name, value in targets.items()],
	'references': [
		{'type': 'URL', 'ref': 'https://github.com/securestate/crimson-forge'}
	]
}

def run(msf_options):
	module.LogHandler.setup(level=msf_options['LOG_LEVEL'], name=msf_options['LOG_NAME'])

	target = targets[msf_options['target']['name']]
	cli_args = target['options'].copy()
	cli_args.extend(['--format', 'raw'])
	cli_args.extend(['--output-format', 'pe:exe'])
	cli_args.append(msf_options['FILENAME'])
	input_data = binascii.a2b_base64(msf_options['payload_raw'])
	try:
		cli.main(cli_args, input_data=input_data, printer=printer)
	except Exception:
		logging.error('cli.main had an error', exc_info=True)
	else:
		printer.print_status('Payload written to: ' + msf_options['FILENAME'])

if __name__ == '__main__':
	os.chdir(os.environ.get('OWD'))
	module.run(metadata, run)
