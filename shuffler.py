import argparse
import random

import crimson_forge

import archinfo

architectures = {
	'x86': archinfo.ArchX86()
}

def main():
	parser = argparse.ArgumentParser(description='Crimson Forge Shuffler', conflict_handler='resolve')
	parser.add_argument('-a', '--arch', dest='arch', default='x86', metavar='value', choices=architectures.keys(), help='the architecture')
	parser.add_argument('-v', '--version', action='version', version='%(prog)s Version: ' + crimson_forge.__version__)
	parser.add_argument('--seed', dest='prng_seed', default=19900614, metavar='value', type=int, help='the prng seed')
	parser.add_argument('input', type=argparse.FileType('rb'), help='the input file')
	parser.add_argument('output', type=argparse.FileType('wb'), help='the output file')
	args = parser.parse_args()

	if args.prng_seed:
		random.seed(args.prng_seed)

	arch = architectures[args.arch]
	binary = crimson_forge.Binary(args.input.read(), arch)
	new_binary = binary.shuffle()
	args.output.write(new_binary.bytes)

if __name__ == '__main__':
	main()
