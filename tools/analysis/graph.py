#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  tools/analysis/graph.py
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
import io
import os
import sys
import warnings
import xml.dom.minidom

relpath = functools.partial(os.path.join, os.path.dirname(os.path.realpath(__file__)), '..', '..')
sys.path.append(relpath())

with warnings.catch_warnings():
	warnings.simplefilter('ignore')
	import crimson_forge
	import crimson_forge.cli as cli
	import crimson_forge.utilities as utilities

architectures = utilities.architectures

EPILOG = """\
graph type choices:
  graphml   the GraphML format (extension: .graphml)
  graphviz  the GraphViz DOT format (extension: .gv)

Generate a graph after analyzing the input file.

example usage:
  ./graph.py -a x86 block_api.x86.bin graphml block_api.x86.graphml
"""

def main():
	parser = argparse.ArgumentParser(
		'crimson-forge',
		description="Crimson Forge Constraint Graph Generator v{0}".format(crimson_forge.__version__),
		conflict_handler='resolve',
		formatter_class=argparse.RawTextHelpFormatter,
		fromfile_prefix_chars='@',
		epilog=EPILOG
	)
	parser.add_argument('-a', '--arch', dest='arch', default='x86', metavar='value', choices=architectures.keys(), help='the architecture')
	parser.add_argument('input', type=argparse.FileType('r'), help='the raw input file')
	parser.add_argument('graph_type', choices=('graphml', 'graphviz'), help='the graph type to write')
	parser.add_argument('output', nargs='?', default=sys.stdout, type=argparse.FileType('w'), help='the output file')

	args = parser.parse_args()
	printer = utilities

	forward_args = ['--skip-analysis', '--skip-banner']
	forward_args.extend(['--arch', args.arch])
	forward_args.extend(['--format', 'raw'])
	forward_args.extend([args.input.name])
	exec_seg = cli.main(forward_args)

	digraph = exec_seg.blocks.to_digraph()
	if args.graph_type == 'graphml':
		graph_text = str(digraph.to_graphml())
		dom = xml.dom.minidom.parse(io.StringIO(graph_text))
		graph_text = dom.toprettyxml(indent='  ')
	elif args.graph_type == 'graphviz':
		graph_text = digraph.to_graphviz().source

	args.output.write(graph_text)

if __name__ == '__main__':
	main()
