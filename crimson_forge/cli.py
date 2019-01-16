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
import gc
import math
import os
import random

import crimson_forge

import archinfo
import boltons.timeutils
import boltons.strutils

architectures = {
	'x86': archinfo.ArchX86()
}

def main():
	start_time = datetime.datetime.utcnow()
	parser = argparse.ArgumentParser('crimson-forge', description='Crimson Forge CLI', conflict_handler='resolve', fromfile_prefix_chars='@')
	gc_group = parser.add_argument_group('garbage collector options')
	gc_group.add_argument('--gc-debug-leak', action='store_const', const=gc.DEBUG_LEAK, default=0, help='set the DEBUG_LEAK flag')
	gc_group.add_argument('--gc-debug-stats', action='store_const', const=gc.DEBUG_STATS, default=0, help='set the DEBUG_STATS flag')

	parser.add_argument('-a', '--arch', dest='arch', default='x86', metavar='value', choices=architectures.keys(), help='the architecture')
	parser.add_argument('-v', '--version', action='version', version='%(prog)s Version: ' + crimson_forge.__version__)
	parser.add_argument('--prng-seed', dest='prng_seed', default=os.getenv('CF_PRNG_SEED', None), metavar='value', type=int, help='the prng seed')
	parser.add_argument('input', type=argparse.FileType('rb'), help='the input file')
	parser.add_argument('output', nargs='?', type=argparse.FileType('wb'), help='the optional output file')

	args = parser.parse_args()
	gc.set_debug(args.gc_debug_stats | args.gc_debug_leak)

	crimson_forge.print_status("crimson-forge engine: v{0}".format(crimson_forge.__version__))

	if args.prng_seed:
		random.seed(args.prng_seed)
		crimson_forge.print_status("seeding the random number generator with {0} (0x{0:x})".format(args.prng_seed))

	arch = architectures[args.arch]
	binary = crimson_forge.Binary(args.input.read(), arch)

	permutation_count = binary.permutation_count()
	instruction_count = len(binary.instructions)
	crimson_forge.print_status("total instructions: {0:,}".format(instruction_count))
	crimson_forge.print_status("possible permutations: {0:,}".format(permutation_count))
	score = math.log(permutation_count, math.factorial(instruction_count))
	crimson_forge.print_status("randomization potential score: {0:0.5f}".format(score))

	new_binary = binary.permutation()
	if args.output:
		args.output.write(new_binary.bytes)

	elapsed = boltons.timeutils.decimal_relative_time(start_time, datetime.datetime.utcnow())
	crimson_forge.print_status("completed in {0:.3f} {1}".format(*elapsed))
