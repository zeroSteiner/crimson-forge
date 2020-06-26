#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  tools/servicizer.py
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
import functools
import os
import sys
import warnings

relpath = functools.partial(os.path.join, os.path.dirname(os.path.realpath(__file__)), '..')
sys.path.append(relpath())

with warnings.catch_warnings():
	warnings.simplefilter('ignore')
	import crimson_forge
	import crimson_forge.cli as cli
	import crimson_forge.servicizer as servicizer
	import crimson_forge.utilities as utilities

import keystone

architectures = utilities.architectures

def main():
	parser = argparse.ArgumentParser(
		'crimson-forge',
		description="Crimson Forge Servicizer v{0}".format(crimson_forge.__version__),
		conflict_handler='resolve',
		formatter_class=argparse.RawTextHelpFormatter,
		fromfile_prefix_chars='@'
	)
	parser.add_argument('-a', '--arch', dest='arch', default='x86', metavar='value', choices=architectures.keys(), help='the architecture')
	parser.add_argument('input', type=argparse.FileType('rb'), help='the payload to convert')
	cli.add_output_arguments(parser, required=True)

	args = parser.parse_args()
	printer = utilities

	arch = architectures[args.arch]
	payload = args.input.read()
	try:
		assembled = servicizer.to_windows_service(arch, payload, )
	except keystone.KsError as error:
		printer.print_error("Error: {}".format(error.message))
		return
	cli.handle_output(args, printer, arch, assembled)

if __name__ == '__main__':
	main()
