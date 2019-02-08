#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  tools/asssembler.py
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
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import crimson_forge
import crimson_forge.cli as cli
import crimson_forge.source as source
import crimson_forge.utilities as utilities

import keystone

architectures = cli.architectures

def main():
	parser = argparse.ArgumentParser(
		'crimson-forge',
		description="Crimson Forge Assembler v{0}".format(crimson_forge.__version__),
		conflict_handler='resolve',
		formatter_class=argparse.RawTextHelpFormatter,
		fromfile_prefix_chars='@'
	)
	parser.add_argument('-a', '--arch', dest='arch', default='x86', metavar='value', choices=architectures.keys(), help='the architecture')
	parser.add_argument('input', type=argparse.FileType('r'), help='the input file')
	parser.add_argument('output', type=argparse.FileType('wb'), help='the output file')
	args = parser.parse_args()
	printer = crimson_forge.utilities

	arch = architectures[args.arch]
	text = args.input.read()
	text = source.remove_comments(text)
	try:
		assembled = bytes(arch.keystone.asm(text, 0x1000)[0])
	except keystone.KsError as error:
		printer.print_error("Error: {}".format(error.message))
		asm_count = error.get_asm_count()
		if asm_count is not None:
			lines = text.split('\n')
			start = max(0, asm_count - 3)
			end = min(len(lines), asm_count + 3)
			for lineno, line in enumerate(lines[start:end], start):
				print(" {: >2} {: >4}: {}".format(('->' if lineno == asm_count else ''), lineno, line))
		return

	args.output.write(assembled)

if __name__ == '__main__':
	main()
