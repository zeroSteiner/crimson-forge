#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  crimson_forge/ir.py
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

import pyvex
import pyvex.lifting.util.vex_helper

OPT_LEVEL_NO_OPTIMIZATION = 0

class JumpKind(pyvex.lifting.util.JumpKind):
	MapFail = 'Ijk_MapFail'

# hashable, immutable
class IRRegister(object):
	def __init__(self, arch, positions):
		self._arch = arch
		self._positions = positions

	def __and__(self, other):
		return bool(set(self._positions).intersection(other._positions))

	def __contains__(self, other):
		return bool(set(self._positions).issuperset(other._positions))

	def __eq__(self, other):
		return self._positions == other._positions

	def __hash__(self):
		return hash((self._positions, (self._arch.name, self._arch.bits, self._arch.memory_endness)))

	def __repr__(self):
		return "<{0} name: {1!r} width: {2} >".format(self.__class__.__name__, self.name, self.width)

	@property
	def arch(self):
		return self._arch

	@property
	def name(self):
		return self.arch.translate_register_name(self._positions.start // 8, self.width // 8)

	@property
	def width(self):
		return len(self._positions)

	@classmethod
	def from_arch(cls, arch, name):
		offset, size = arch.registers[name]
		offset *= 8
		return cls(arch, range(offset, offset + (size * 8)))

	@classmethod
	def from_ir(cls, arch, offset, size=None):
		if size is None:
			size = arch.bits
		return cls(arch, range(offset, offset + size))

	@classmethod
	def from_ir_expr_get(cls, arch, expr, ir_tyenv):
		return cls.from_ir(arch, expr.offset * 8, expr.result_size(ir_tyenv))

	@classmethod
	def from_ir_stmt_exit(cls, arch, stmt, ir_tyenv):
		return cls.from_ir(arch, stmt.offsIP * 8)

	@classmethod
	def from_ir_stmt_put(cls, arch, stmt, ir_tyenv):
		return cls.from_ir(arch, stmt.offset * 8, stmt.data.result_size(ir_tyenv))

	def in_iterable(self, iterable):
		return any(self & other_reg for other_reg in iterable)

def lift(blob, base, arch):
	return pyvex.lift(blob, base, arch, opt_level=OPT_LEVEL_NO_OPTIMIZATION)

def irsb_to_instructions(irsb):
	"""
	Take a lifted *irsb* object and return an
	:py:class:`~collections.OrderedDict` keyed by the address instructions with
	values of :py:class:`~collections.deque`s containing the IR statements.

	:param irsb: The IR super-block to get instructions for.
	:rtype: :py:class:`~collections.OrderedDict`
	"""
	ir_instructions = collections.OrderedDict()
	for statement in irsb.statements:
		if isinstance(statement, pyvex.stmt.IMark):
			address = statement.addr
			ir_instructions[address] = collections.deque()
		ir_instructions[address].append(statement)
	return ir_instructions
