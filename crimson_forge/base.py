#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  crimson_forge/base.py
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

import binascii
import collections
import collections.abc
import sys

import crimson_forge.instruction as instruction

import tabulate

class InstructionsProxy(collections.abc.Mapping):
	"""
	A mapping of addresses to :py:class:`~.instruction.Instruction` instances.
	"""
	def __init__(self, arch, cs_instructions):
		"""
		:param arch: The architecture of the instructions.
		:type arch: :py:class:`archinfo.Arch`
		:param tuple cs_instructions: The iterable of Capstone instructions to map.
		"""
		self.arch = arch
		self.cs_instructions = cs_instructions

	def __contains__(self, key):
		return key in self.cs_instructions

	def __getitem__(self, address):
		return instruction.Instruction(self.arch, self.cs_instructions[address], *self._resolve_ir(address))

	def __iter__(self):
		yield from self.cs_instructions.keys()

	def __len__(self):
		return len(self.cs_instructions)

	def __repr__(self):
		return "<{0} arch: {1} >".format(self.__class__.__name__, self.arch.name)

	def __reversed__(self):
		yield from reversed(self.cs_instructions.keys())

	def _resolve_ir(self, address):
		raise NotImplementedError()

	def for_address(self, address):
		"""
		Obtain the instruction which exists at *address*. This method does not
		require *address* to be the start of the instruction, like using the
		get item interface does. If no instruction is found at the specified
		*address*, ``None`` is returned.

		:param int address: The address to obtain the instruction for.
		:return: The instruction located at the specified address.
		:rtype: :py:class:`crimson_forge.instruction.Instruction`
		"""
		for ins in self.cs_instructions.values():
			if ins.address <= address <= (ins.address + ins.size - 1):
				return self.__getitem__(ins.address)
		return None

	def pp_asm(self, stream='stdout'):
		"""
		Pretty-print the disassembly of the instructions to the specified
		*stream*. This method is intended for debugging purposes.

		:param str stream: The stream to write to. If stream is ``None``, no output is displayed.
		:return: The formatted output that was optionally written to *stream*.
		:rtype: str
		"""
		table = [("0x{:04x}".format(ins.address), ins.bytes_hex, ins.source) for ins in self.values()]
		formatted = tabulate.tabulate(table, disable_numparse=True, tablefmt='plain')
		if stream is not None:
			if isinstance(stream, str) and stream.lower() in ('stderr', 'stdout'):
				stream = getattr(sys, stream.lower())
			print(formatted, file=stream)
		return formatted

	def pp_ir(self):
		"""
		Pretty-print the intermediary representation (IR) of the instructions.
		This method is intended for debugging purposes.
		"""
		for ins in self.values():
			ins.pp_ir()

class Base(object):
	"""
	A base class for representing some the binary data of some instructions.
	"""
	def __init__(self, blob, arch, address):
		self.bytes = blob
		self.arch = arch
		self.address = address
		self.cs_instructions = collections.OrderedDict()
		self.vex_instructions = collections.OrderedDict()

	def __repr__(self):
		return "<{0} arch: {1}, at: 0x{2:04x}, size: {3} >".format(self.__class__.__name__, self.arch.name, self.address, self.size)

	@property
	def bytes_hex(self):
		return binascii.b2a_hex(self.bytes)

	@property
	def next_address(self):
		return self.address + self.size

	@property
	def size(self):
		return len(self.bytes)
