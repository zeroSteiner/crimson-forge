#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  crimson_forge/source.py
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

import collections
import enum
import logging

import archinfo
import tabulate

logger = logging.getLogger('crimson-forge.source')

def remove_comments(source, comment_char=';'):
	"""Remove comments from assembly source."""
	# todo: this should use a regex incase theres a ';' in the source
	lines = source.split('\n')
	return '\n'.join([line.split(comment_char, 1)[0].rstrip() for line in lines])

def label_maker(location, prefix='loc', scope=''):
	return "{}_{}{:04x}".format(prefix, scope, location)

@enum.unique
class ReferenceType(enum.Enum):
	ADDRESS = 'address'              # the value is an absolute address, go there
	BLOCK = 'block'                  # the value is a block, go to it's first instruction
	BLOCK_ADDRESS = 'block-address'  # the value is an address, go to the first instruction of the block it's in
	INSTRUCTION = 'instruction'      # the value is a specific instruction, go there

# this is a reference target used to provide context for how labels should be
# generated based on what they're referring to
Reference = collections.namedtuple('Reference', ('type', 'value'))

class SourceLine(object):
	__slots__ = ('code', 'comment')
	def __init__(self, code, comment=None):
		self.code = code
		self.comment = comment

	@property
	def text(self):
		return

class SourceLineLabel(SourceLine):
	def __init__(self, label, comment=None):
		self.code = label + ':'
		self.comment = comment

class SourceCode(object):
	def __init__(self, arch):
		self.arch = arch
		# These three _ref_ attributes map various *things* to SourceLine instances. This allows the SourceLine
		# instances to be referred to in multiple ways (as defined by ReferenceType). The default (address) is
		# used to look up the block to which an address belongs before the block is used. Under normal conditions, the
		# destination would by definition be the first address in a block, but in the case where a the source was
		# randomized the address may have been moved deeper in the block.
		self._ref_addresses = collections.defaultdict(collections.deque)
		self._ref_blocks = {}
		self._ref_block_addresses = collections.defaultdict(collections.deque)
		self._ref_instructions = {}
		self._lines = []
		self._labels = {}
		self._relative_references = 1
		self._instructions = {}

	def extend(self, things, block=None):
		for idx, thing in enumerate(things):
			if isinstance(thing, SourceLine):
				self._lines.append(thing)
				continue
			if not isinstance(self.arch, (archinfo.ArchAMD64, archinfo.ArchX86)):
				raise NotImplementedError()
			jmp_reference = thing.jmp_reference
			if jmp_reference is not None:
				if jmp_reference.type == ReferenceType.ADDRESS:
					label = label_maker(jmp_reference.value)
				elif jmp_reference.type == ReferenceType.BLOCK:
					label = label_maker(self._relative_references, scope='rel')
					self._relative_references += 1
				elif jmp_reference.type == ReferenceType.BLOCK_ADDRESS:
					label = label_maker(jmp_reference.value)
				elif jmp_reference.type == ReferenceType.INSTRUCTION:
					label = label_maker(self._relative_references, scope='rel')
					self._relative_references += 1
				else:
					raise TypeError('unknown jump reference type')
				self._labels[jmp_reference] = label
				# todo: fix this disgusting hack
				match = thing._regex_jmp.match(thing.source)
				src_line = SourceLine("{} {}".format(match.group('jump'), label), comment=match.group('comment'))
			else:
				src_line = SourceLine(thing.source)
			if block:
				if idx == 0:
					self._ref_blocks[block.address] = src_line
				self._ref_block_addresses[thing.address] = self._ref_blocks[block.address]
			self._ref_instructions[thing] = src_line
			self._ref_addresses[thing.address].append(src_line)
			self._lines.append(src_line)

	def __str__(self):
		src_lines = self._lines.copy()
		for jmp_reference, label in self._labels.items():
			src_line = None
			if jmp_reference.type == ReferenceType.ADDRESS:
				if jmp_reference.value in self._ref_addresses:
					src_line = self._ref_addresses[jmp_reference.value][0]
			elif jmp_reference.type == ReferenceType.BLOCK:
				src_line = self._ref_blocks.get(jmp_reference.value.address)
			elif jmp_reference.type == ReferenceType.BLOCK_ADDRESS:
				src_line = self._ref_block_addresses.get(jmp_reference.value)
			elif jmp_reference.type == ReferenceType.INSTRUCTION:
				src_line = self._ref_instructions.get(jmp_reference.value)
			else:
				raise TypeError('unknown jump reference type')
			if src_line is None:
				logger.error('Have no known position for reference label: ' + label)
			else:
				src_lines.insert(src_lines.index(src_line), SourceLineLabel(label))

		text_lines = collections.deque()
		for src_line in src_lines:
			comment = '' if src_line.comment is None else '; ' + src_line.comment
			if isinstance(src_line, SourceLineLabel):
				text_lines.append((src_line.code, comment))
			else:
				text_lines.append(('  ' + src_line.code, comment))
		return tabulate.tabulate(text_lines, disable_numparse=True, stralign=None, tablefmt='plain') + '\n'
