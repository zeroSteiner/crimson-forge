#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  crimson_forge/cli.py
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
import datetime
import enum
import gc
import hashlib
import logging
import math
import os
import random

import crimson_forge
import crimson_forge.utilities

import archinfo
import boltons.timeutils
import boltons.strutils
import smoke_zephyr.utilities

HELP_EPILOG = """\
data format choices:
  raw        raw executable code
  source     assembly source code
"""

architectures = {
	'amd64': archinfo.ArchAMD64(),
	'x86': archinfo.ArchX86(),
}

@enum.unique
class DataFormat(enum.Enum):
	RAW = 'raw'
	SOURCE = 'source'

data_formats = tuple(format.value for format in DataFormat)
def argtype_data_format(value):
	try:
		format_type = DataFormat(value)
	except ValueError:
		raise argparse.ArgumentTypeError("{0!r} is not a valid data format".format(value)) from None
	return format_type

def hash(data, algorithm='sha256'):
	return hashlib.new(algorithm, data).hexdigest()

def main():
	start_time = datetime.datetime.utcnow()
	parser = argparse.ArgumentParser(
		'crimson-forge',
		description='Crimson Forge CLI',
		conflict_handler='resolve',
		epilog=HELP_EPILOG,
		formatter_class=argparse.RawTextHelpFormatter,
		fromfile_prefix_chars='@'
	)
	gc_group = parser.add_argument_group('garbage collector options')
	gc_group.add_argument('--gc-debug-leak', action='store_const', const=gc.DEBUG_LEAK, default=0, help='set the DEBUG_LEAK flag')
	gc_group.add_argument('--gc-debug-stats', action='store_const', const=gc.DEBUG_STATS, default=0, help='set the DEBUG_STATS flag')
	log_group = parser.add_argument_group('logging options')
	log_group.add_argument('--log-level', default=logging.WARNING, choices=('DEBUG', 'INFO', 'WARNING', 'ERROR', 'FATAL'), help='set the log level')
	log_group.add_argument('--log-name', default='', help='specify the root logger')

	parser.add_argument('-a', '--arch', dest='arch', default='x86', metavar='value', choices=architectures.keys(), help='the architecture')
	parser.add_argument('-f', '--format', dest='input_format', default=DataFormat.RAW, metavar='FORMAT', type=argtype_data_format, help='the input format')
	parser.add_argument('-v', '--version', action='version', version='%(prog)s Version: ' + crimson_forge.__version__)
	parser.add_argument('--prng-seed', dest='prng_seed', default=os.getenv('CF_PRNG_SEED', None), metavar='VALUE', type=int, help='the prng seed')
	parser.add_argument('input', type=argparse.FileType('rb'), help='the input file')
	parser.add_argument('output', nargs='?', type=argparse.FileType('wb'), help='the optional output file')

	args = parser.parse_args()
	smoke_zephyr.utilities.configure_stream_logger(
		logger=args.log_name,
		level=args.log_level,
		formatter=crimson_forge.utilities.ColoredLogFormatter('%(levelname)s %(message)s')
	)
	gc.set_debug(args.gc_debug_stats | args.gc_debug_leak)

	crimson_forge.print_status("crimson-forge engine: v{0}".format(crimson_forge.__version__))

	if args.prng_seed:
		random.seed(args.prng_seed)
		crimson_forge.print_status("seeding the random number generator with {0} (0x{0:x})".format(args.prng_seed))

	arch = architectures[args.arch]
	if args.input_format is DataFormat.RAW:
		data = args.input.read()
		crimson_forge.print_status('input hash (sha-256): ' + hash(data))
		binary = crimson_forge.Binary(data, arch)
	elif args.input_format is DataFormat.SOURCE:
		binary = crimson_forge.Binary.from_source(args.input.read().decode('utf-8'), arch)

	crimson_forge.print_status("total basic-blocks: {0:,}".format(len(binary.blocks)))
	permutation_count = binary.permutation_count()
	instruction_count = len(binary.instructions)
	crimson_forge.print_status("total instructions: {0:,}".format(instruction_count))
	crimson_forge.print_status("possible permutations: {0:,}".format(permutation_count))
	score = math.log(permutation_count, math.factorial(instruction_count))
	crimson_forge.print_status("randomization potential score: {0:0.5f}".format(score))

	new_binary = binary.permutation()
	if args.output:
		data = new_binary.bytes
		crimson_forge.print_status('output hash (sha-256): ' + hash(data))
		args.output.write(data)
	else:
		crimson_forge.print_status('no output file specified')

	elapsed = boltons.timeutils.decimal_relative_time(start_time, datetime.datetime.utcnow())
	crimson_forge.print_status("completed in {0:.3f} {1}".format(*elapsed))
