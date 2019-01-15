import argparse
import datetime
import math
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
	parser = argparse.ArgumentParser(description='Crimson Forge Shuffler', conflict_handler='resolve')
	parser.add_argument('-a', '--arch', dest='arch', default='x86', metavar='value', choices=architectures.keys(), help='the architecture')
	parser.add_argument('-v', '--version', action='version', version='%(prog)s Version: ' + crimson_forge.__version__)
	parser.add_argument('--seed', dest='prng_seed', default=19900614, metavar='value', type=int, help='the prng seed')
	parser.add_argument('input', type=argparse.FileType('rb'), help='the input file')
	parser.add_argument('output', type=argparse.FileType('wb'), help='the output file')
	args = parser.parse_args()

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
	args.output.write(new_binary.bytes)

	elapsed = boltons.timeutils.decimal_relative_time(start_time, datetime.datetime.utcnow())
	crimson_forge.print_status("completed in {0:.3f} {1}".format(*elapsed))

if __name__ == '__main__':
	main()
