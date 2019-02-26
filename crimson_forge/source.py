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

logger = logging.getLogger('crimson-forge.source')

REGEX_INSTRUCTION_END = r'(\s+;(?P<comment>.*))?$'

def remove_comments(text: str, comment_char: str = ';') -> str:
	"""
	Remove comments from the provided assembly source text.

	:param text: The text to remove comments from.
	:param comment_char: The character marking the start of a comment.
	:return: The source text without comments.
	"""
	# todo: this should use a regex incase theres a ';' in the source
	lines = text.split('\n')
	return '\n'.join([line.split(comment_char, 1)[0].rstrip() for line in lines])

def label_maker(location: int, prefix: str = 'loc', scope: str = '') -> str:
	"""
	Create a label uniquely identifying a location. While the location may be
	included in the resulting label, the label is not meant to be parsed and
	should be treated as an opaque piece of data.

	:param location: The location this label refers to, it must be unique among labels.
	:param prefix: The prefix to place before the label to provide context.
	:param scope: An optional scope for the label.
	:return: A string to identity.
	"""
	return "{}_{}{:04x}".format(prefix, scope, location)

@enum.unique
class ReferenceType(enum.Enum):
	"""The type of the reference."""
	ADDRESS = 'address'              # the value is an absolute address, go there
	"""A specific address (relative to the location of the referring instruciton)."""
	BLOCK = 'block'                  # the value is a block, go to it's first instruction
	"""A specific block. Resolution will evaluate to the first instruction of the block."""
	BLOCK_ADDRESS = 'block-address'  # the value is an address, go to the first instruction of the block it's in
	"""An address in a block. Resolution will evaluate to the first instruction of the block containing the specified address."""
	INSTRUCTION = 'instruction'      # the value is a specific instruction, go there
	"""A specific instruction. Resolution will evaluate to the specified instruction instance."""

class Reference(object):
	"""
	A reference to another location in code. This provides context for how
	labels should be generated.
	"""
	__slots__ = ('__weakref__', '_type', '_value')
	def __init__(self, type: ReferenceType, value):
		"""
		:param type: The type of *value*, i.e. how it should be resolved.
		:param value: The value of the reference (what is being referred to).
		"""
		self._type = type
		self._value = value

	@property
	def type(self):
		return self._type

	@property
	def value(self):
		return self._value

# immutable
class SourceLine(object):
	"""A instruction and line of assembly source code."""
	__slots__ = ('__weakref__', '_code', '_comment')
	def __init__(self, code: str, comment: str = None):
		"""
		:param code: The assembly code on this line.
		:param comment: An optional comment to include when outputting raw code to provide context to human readers.
		"""
		self._code = code
		self._comment = comment

	@property
	def code(self):
		return self._code

	@property
	def comment(self):
		return self._comment

# immutable
class SourceLineComment(SourceLine):
	"""
	A line without any code that is simply a comment to provide context to
	humans.
	"""
	def __init__(self, comment: str):
		"""
		:param comment: An optional comment to include when outputting raw code to provide context to human readers.
		"""
		super(SourceLineComment, self).__init__('', comment=comment)

# immutable
class SourceLineLabel(SourceLine):
	"""A line of assembly code containing a label definition."""
	def __init__(self, label: str, comment: str = None):
		"""
		:param label: The label on this line.
		:param comment: An optional comment to include when outputting raw code to provide context to human readers.
		"""
		super(SourceLineLabel, self).__init__(label + ':', comment=comment)

	@property
	def label(self):
		return self._code[:-1]

class SourceCode(object):
	"""
	An object representing the source code representation of a series of
	instructions of the specified architecture. When this object is converted to
	a string, labels and references are processed and placed in their
	corresponding locations.
	"""
	def __init__(self, arch):
		self.arch = arch
		# These three _ref_ attributes map various *things* to SourceLine instances. This allows the SourceLine
		# instances to be referred to in multiple ways (as defined by ReferenceType). The default (block-address) is
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
		"""
		Add *things* to be included in the source code. The order in which they
		are added will be the order in which their lines appear in the output.

		:param things: An iterable of objects to add.
		:param block: The block that *things* are associated with (used for reference building).
		:type block: :py:class:`~crimson_forge.block.BlockBase`
		"""
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
		placed_labels = set()
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
				continue
			position = src_lines.index(src_line)
			if position > 1:
				prev_src_line = src_lines[position - 1]
				if isinstance(prev_src_line, SourceLineLabel) and prev_src_line.label == label:
					# skip duplicate labels which have resolved to the same location
					continue
			elif label in placed_labels:
				message = "Source label '{}' has been redefined".format(label)
				logger.error(message)
				raise RuntimeError(message)
			src_lines.insert(src_lines.index(src_line), SourceLineLabel(label))
			placed_labels.add(label)

		text_lines = collections.deque()
		for src_line in src_lines:
			comment = '' if src_line.comment is None else '; ' + src_line.comment
			if isinstance(src_line, SourceLineComment):
				text_lines.append((comment, ''))
			elif isinstance(src_line, SourceLineLabel):
				text_lines.append((src_line.code, comment))
			else:
				text_lines.append(('  ' + src_line.code, comment))
		alignment = max(len(text_line[0]) for text_line in text_lines) + 1
		output = ''
		for code, comment in text_lines:
			output += "{code: <{alignment}}  {comment}".format(code=code, alignment=alignment, comment=comment).rstrip() + '\n'
		return output
