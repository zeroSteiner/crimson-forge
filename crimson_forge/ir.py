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
import re

import archinfo
import pyvex
import pyvex.lifting.util.vex_helper

OPT_LEVEL_NO_OPTIMIZATION = 0

# https://github.com/angr/pyvex/blob/master/pyvex/lifting/util/vex_helper.py
class JumpKind(pyvex.lifting.util.JumpKind):
	"""
	A class containing the various jump kinds that can be encountered in the IR.
	"""
	MapFail = 'Ijk_MapFail'

	@classmethod
	def returns(cls, value):
		"""
		Whether or not the jump kind *value* returns the flow of execution.

		:param str value: The jump kind to check.
		:return: Whether or not the jump kind returns the flow of execution.
		:rtype: bool
		"""
		return value in (cls.Call, cls.Syscall, cls.Sysenter)

# hashable, immutable
class IRJump(object):
	"""
	An object representing an IR jump and it's associated metadata.
	"""
	__slots__ = ('_arch', '_from_address', '_to_address', '_kind')
	def __init__(self, arch, to_address, from_address, kind=JumpKind.Boring):
		"""
		:param arch: The architecture of the jump.
		:type arch: :py:class:`archinfo.Arch`
		:param int to_address: The jump's destination address.
		:param int from_address: The jump's source address.
		:param str kind: The kind of jump, corresponding to a :py:class:`.JumpKind` attribute.
		"""
		self._arch = arch
		self._to_address = to_address
		self._from_address = from_address
		self._kind = kind

	def __hash__(self):
		return hash(((self._arch.name, self._arch.bits, self._arch.memory_endness), self._to_address, self._from_address))

	def __repr__(self):
		return "<{} 0x{:04x} -> 0x{:04x} ({}) >".format(self.__class__.__name__, self._from_address, self._to_address, self._kind)

	@property
	def arch(self):
		return self._arch

	@property
	def from_address(self):
		return self._from_address

	@property
	def kind(self):
		return self._kind

	@property
	def to_address(self):
		return self._to_address

# hashable, immutable
class IRRegister(object):
	"""An object representing an IR register and it's associated metadata."""
	__slots__ = ('__weakref__', '_arch', '_name', '_positions')
	def __init__(self, arch, positions, name=None):
		"""
		:param arch: The architecture of the register.
		:type arch: :py:class:`archinfo.Arch`
		:param range positions: The bit positions occupied by the register.
		:param str name: An optional explicit name for the register.
		"""
		self._arch = arch
		self._name = name
		self._positions = positions

	def __and__(self, other):
		return bool(set(self._positions).intersection(other._positions))

	def __contains__(self, other):
		return bool(set(self._positions).issuperset(other._positions))

	def __eq__(self, other):
		if not isinstance(other, IRRegister):
			return False
		return hash(self) == hash(other)

	def __hash__(self):
		return hash(((self._arch.name, self._arch.bits, self._arch.memory_endness), self._positions))

	def __repr__(self):
		return "<{0} name: {1!r} width: {2} >".format(self.__class__.__name__, self.name, self.width)

	@property
	def arch(self):
		"""
		:return: The architecture of this register.
		:rtype: :py:class:`archinfo.Arch`
		"""
		return self._arch

	@classmethod
	def from_arch(cls, arch, name):
		"""
		:param arch: The architecture of the register.
		:type arch: :py:class:`archinfo.Arch`
		:param str name: The name of the register to create for the architecture.
		:rtype: :py:class:`.IRRegister`
		"""
		offset, size = arch.registers[name]
		offset *= arch.byte_width
		return cls(arch, range(offset, offset + (size * arch.byte_width)))

	@classmethod
	def from_ir(cls, arch, offset, size=None):
		"""
		:param arch: The architecture of the register.
		:type arch: :py:class:`archinfo.Arch`
		:param int offset: The offset in bits of the register within the IR.
		:param int size: The number of bits the register occupies, e.g. x86's ``eax`` register would be 32-bits.
		:rtype: :py:class:`.IRRegister`
		"""
		if size is None:
			size = arch.bits
		return cls(arch, range(offset, offset + size))

	@classmethod
	def from_ir_expr_get(cls, arch, expr, ir_tyenv):
		return cls.from_ir(arch, expr.offset * arch.byte_width, expr.result_size(ir_tyenv))

	@classmethod
	def from_ir_expr_geti(cls, arch, expr, ir_tyenv):
		offset = expr.descr.base * arch.byte_width
		size = pyvex.const.get_type_size(expr.descr.elemTy) * expr.descr.nElems
		return cls.from_ir(arch, offset, size=size)

	@classmethod
	def from_ir_stmt_exit(cls, arch, stmt, ir_tyenv):
		return cls.from_ir(arch, stmt.offsIP * arch.byte_width)

	@classmethod
	def from_ir_stmt_put(cls, arch, stmt, ir_tyenv):
		return cls.from_ir(arch, stmt.offset * arch.byte_width, stmt.data.result_size(ir_tyenv))

	@classmethod
	def from_ir_stmt_puti(cls, arch, stmt, ir_tyenv):
		# PutI statements are reading from a variable location within the guest
		# state, this treats the entire range as a single registers tracking the
		# entire range as a single segment
		# see: https://github.com/angr/vex/blob/4bdf4da8e0208e8ebf0a728d0477aebfba890f93/pub/libvex_ir.h#L2001-L2035
		offset = stmt.descr.base * arch.byte_width
		size = pyvex.const.get_type_size(stmt.descr.elemTy) * stmt.descr.nElems
		return cls.from_ir(arch, offset, size=size)

	def in_iterable(self, iterable):
		"""
		Whether this register overlaps with any register in *iterable*.

		:param iterable: The iterable to check the contents of.
		:return: Whether or not this register overlaps with any register in *iterable*.
		:rtype: bool
		"""
		return any(self & other_reg for other_reg in iterable)

	@property
	def name(self):
		"""
		:return: The name of this register.
		:rtype: str
		"""
		if self._name is not None:
			return self._name
		return self.arch.translate_register_name(self._positions.start // self.arch.byte_width, self.width // self.arch.byte_width)

	@property
	def width(self):
		"""
		:return: The width in bits of this register.
		:rtype: int
		"""
		return len(self._positions)

def lift(blob, base, arch):
	return pyvex.lift(blob, base, arch, collect_data_refs=True, opt_level=OPT_LEVEL_NO_OPTIMIZATION)

def irsb_address_for_statement(irsb, stmt):
	"""
	Take a lifted *irsb* object and return the address of the instruction to
	which *stmt* belongs.

	:param irsb: The IR super-block to which *stmt* belongs.
	:param stmt: The IR statement to get the instruction address for.
	:rtype: int
	"""
	address = None
	for o_stmt in irsb.statements:
		if isinstance(o_stmt, pyvex.stmt.IMark):
			address = o_stmt.addr
		if o_stmt is stmt:
			return address
	return None

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
