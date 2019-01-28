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
import crimson_forge.analysis
import crimson_forge.binfile
import crimson_forge.utilities

import archinfo
import boltons.iterutils
import boltons.strutils
import boltons.timeutils
import smoke_zephyr.utilities

HELP_EPILOG = """\
analysis profile choices:
  shellcode        analyze the code in the context of inclusive, positionally
                   independent shellcode, i.e. a metasploit payload
  executable-file  analyze the code in the context of a traditional executable
                   file such as a windows portable executable (.exe)

data format choices:
  pe:exe           a portable executable
  raw              raw executable code
  source           assembly source code
"""

architectures = {
	'amd64': archinfo.ArchAMD64(),
	'x86': archinfo.ArchX86(),
}

@enum.unique
class DataFormat(enum.Enum):
	PE_EXE = 'pe:exe'
	RAW = 'raw'
	SOURCE = 'source'

@enum.unique
class AnalysisProfile(enum.Enum):
	SHELLCODE = 'shellcode'
	EXECUTABLE_FILE = 'executable-file'

def argtype_data_format(value):
	try:
		format_type = DataFormat(value.lower())
	except ValueError:
		raise argparse.ArgumentTypeError("{0!r} is not a valid data format".format(value)) from None
	return format_type

def argtype_analysis_profile(value):
	try:
		profile = AnalysisProfile(value.lower())
	except ValueError:
		raise argparse.ArgumentTypeError("{0!r} is not a valid analysis profile".format(value)) from None
	return profile

def hash(data, algorithm='sha256'):
	return hashlib.new(algorithm, data).hexdigest()

def _handle_output(args, printer, arch, data):
	if args.output_format == DataFormat.RAW:
		args.output.write(data)
	elif args.output_format == DataFormat.PE_EXE:
		if not isinstance(arch, (archinfo.ArchAMD64, archinfo.ArchX86)):
			printer.print_error('Unsupported architecture for PE output: ' + arch.name)
			return
		pe_data = crimson_forge.binfile.build_pe_exe_for_shellcode(arch, data)
		printer.print_status('PE output hash (SHA-256): ' + hash(pe_data))
		args.output.write(pe_data)
	else:
		printer.print_error('Unsupported output format: ' + args.input_format)

def main(args=None, input_data=None, printer=None):
	start_time = datetime.datetime.utcnow()
	parser = argparse.ArgumentParser(
		'crimson-forge',
		description="Crimson Forge CLI v{0}".format(crimson_forge.__version__),
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
	log_group.add_argument('--log-name', default='crimson-forge', help='specify the root logger')

	parser.add_argument('-a', '--arch', dest='arch', default='x86', metavar='value', choices=architectures.keys(), help='the architecture')
	parser.add_argument('-f', '--format', dest='input_format', default=DataFormat.RAW, metavar='FORMAT', type=argtype_data_format, help='the input format (see: data format choices)')
	parser.add_argument('-v', '--version', action='version', version='%(prog)s Version: ' + crimson_forge.__version__)
	parser.add_argument('--analysis-profile', dest='analysis_profile', default=None, metavar='PROFILE', type=argtype_analysis_profile, help='the analysis profile to use (see: analysis profile choices)')
	parser.add_argument('--output-format', dest='output_format', default=DataFormat.RAW, metavar='FORMAT', type=argtype_data_format, help='the output format (see: data format choices)')
	parser.add_argument('--prng-seed', dest='prng_seed', default=os.getenv('CF_PRNG_SEED', None), metavar='VALUE', type=int, help='the prng seed')
	parser.add_argument('--skip-analysis', dest='analyze', default=True, action='store_false', help='skip the analysis phase')
	parser.add_argument('--skip-permutation', dest='permutation', default=True, action='store_false', help='skip the permutation generation phase')
	if input_data is None:
		parser.add_argument('input', type=argparse.FileType('rb'), help='the input file')
	parser.add_argument('output', nargs='?', type=argparse.FileType('wb'), help='the optional output file')

	args = parser.parse_args(args)
	smoke_zephyr.utilities.configure_stream_logger(
		logger=args.log_name,
		level=args.log_level,
		formatter=crimson_forge.utilities.ColoredLogFormatter('%(levelname)s [%(name)s] %(message)s')
	)
	gc.set_debug(args.gc_debug_stats | args.gc_debug_leak)
	printer = printer or crimson_forge.utilities

	printer.print_status("Crimson-Forge Engine: v{0}".format(crimson_forge.__version__))
	if args.prng_seed:
		random.seed(args.prng_seed)
		printer.print_status("Seeding the random number generator with {0} (0x{0:x})".format(args.prng_seed))

	analysis_profile = args.analysis_profile
	arch = architectures[args.arch]
	printer.print_status('Architecture set as: ' + arch.name)
	input_data_length = None
	if args.input_format is DataFormat.RAW:
		input_data = input_data or args.input.read()
		input_data_length = len(input_data)
		printer.print_status('Input hash (SHA-256): ' + hash(input_data))
		exec_seg = crimson_forge.ExecutableSegment(input_data, arch)
		analysis_profile = analysis_profile or AnalysisProfile.SHELLCODE
	elif args.input_format is DataFormat.SOURCE:
		input_data = input_data or args.input.read().decode('utf-8')
		exec_seg = crimson_forge.ExecutableSegment.from_source(input_data, arch)
		analysis_profile = analysis_profile or AnalysisProfile.SHELLCODE
	else:
		printer.print_error('Unsupported input format: ' + args.input_format)
		return

	printer.print_status('Using analysis profile: ' + analysis_profile.value + (' (auto-detected)' if args.analysis_profile is None else ''))
	if analysis_profile == AnalysisProfile.SHELLCODE:
		crimson_forge.analysis.symexec_data_identification_ret(exec_seg)

	printer.print_status("Total blocks: {:,}".format(len(exec_seg.blocks)))
	printer.print_status("    basic     {:,}".format(sum(1 for blk in exec_seg.blocks.values() if isinstance(blk, crimson_forge.BasicBlock))))
	printer.print_status("    data:     {:,}".format(sum(1 for blk in exec_seg.blocks.values() if isinstance(blk, crimson_forge.DataBlock))))

	instruction_count = len(exec_seg.instructions)
	printer.print_status("Total instructions: {0:,}".format(instruction_count))
	if args.analyze:
		permutation_count = exec_seg.permutation_count()
		printer.print_status("Possible permutations: {0:,}".format(permutation_count))
		score = math.log(permutation_count, math.factorial(instruction_count))
		printer.print_status("Randomization potential score: {0:0.5f}".format(score))

	if args.output:
		if args.permutation:
			input_data = exec_seg.permutation_bytes()
		else:
			input_data = exec_seg.bytes
		if input_data_length is not None and input_data_length != len(input_data):
			printer.print_error("Raw output length: {} (incorrect, input length: {})".format(boltons.strutils.bytes2human(len(input_data)), boltons.strutils.bytes2human(input_data_length)))
			printer.print_status('Analyzing block sizes...')
			crimson_forge.analysis.check_block_sizes(exec_seg)
		else:
			printer.print_status('Output length: ' + boltons.strutils.bytes2human(len(input_data)) + ' (correct)')
		printer.print_status('Raw output hash (SHA-256): ' + hash(input_data))
		_handle_output(args, printer, arch, input_data)
	else:
		printer.print_status('To output file specified')

	elapsed = boltons.timeutils.decimal_relative_time(start_time, datetime.datetime.utcnow())
	printer.print_status("Completed in {0:.3f} {1}".format(*elapsed))
