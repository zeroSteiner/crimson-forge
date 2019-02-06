#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  crimson_forge/instruction.py
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
import functools
import logging
import sys

import crimson_forge.ir as ir
import crimson_forge.utilities as utilities

import archinfo
import pyvex

logger = logging.getLogger('crimson-forge.instruction')

class TaintTrackingError(RuntimeError):
	pass

def match_mask(data, mask, byte_width=8):
	data = bytearray(data)
	integer = 0
	while data:
		integer <<= byte_width
		integer |= data.pop(0)
	for mask_bit in reversed(mask):
		if mask_bit == ' ':
			continue  # ignore spaces which can be used for breaking up bytes
		real_bit = (integer & 1)
		integer >>= 1
		if mask_bit == '0':
			if real_bit == 0:
				continue
		elif mask_bit == '1':
			if real_bit == 1:
				continue
		else:
			continue
		return False
	return integer == 0

postprocessors = collections.defaultdict(list)
def register_postprocessor(*architectures, byte_mask=None, mnemonic=None):
	if isinstance(mnemonic, str):
		mnemonic = (mnemonic,)
	def decorator(function):
		@functools.wraps(function)
		def wrapper(ins):
			if byte_mask is not None:
				if not match_mask(ins.bytes, byte_mask, byte_width=ins.arch.byte_width):
					return
			if mnemonic is not None:
				if ins.cs_instruction.mnemonic.lower() not in mnemonic:
					return
			logger.info('Using instruction postprocessor: ' + function.__name__)
			return function(ins)
		for arch in architectures:
			postprocessors[arch.name].append(wrapper)
		return wrapper
	return decorator

_InstructionRegisters = collections.namedtuple('InstructionRegisters', ('accessed', 'modified', 'stored'))
# hashable
class Instruction(object):
	def __init__(self, arch, cs_ins, vex_statements, ir_tyenv):
		self.arch = arch
		self.cs_instruction = cs_ins
		self.vex_statements = vex_statements
		self._ir_tyenv = ir_tyenv
		self.dirty = False

		self.registers = _InstructionRegisters(set(), set(), set())
		vex_statements = self._fixup_vex_stmts(vex_statements.copy())
		taint_tracking = {}
		for stmt in vex_statements:
			if isinstance(stmt, pyvex.stmt.AbiHint):
				pass
			elif isinstance(stmt, pyvex.stmt.CAS):
				taint_tracking[stmt.oldLo] = taint_tracking[stmt.dataLo.tmp] | taint_tracking[stmt.expdLo.tmp]
				if not (stmt.oldHi == 0xffffffff or stmt.expdHi is None):
					# double element
					taint_tracking[stmt.oldHi] = taint_tracking[stmt.dataHi.tmp] | taint_tracking[stmt.expdHi.tmp]
			elif isinstance(stmt, pyvex.stmt.Dirty):
				self.dirty = True
				# handle dirty statements on a case-by-case basis
				if stmt.cee.name in ('amd64g_dirtyhelper_FSTENV', 'x86g_dirtyhelper_FSTENV'):
					logger.info('Encountered handled dirty IR statement: ' + stmt.cee.name)
					self.registers.accessed.add(ir.IRRegister.from_arch(self.arch, 'ftop'))
					self.registers.stored.add(ir.IRRegister.from_arch(self.arch, 'ftop'))
				else:
					logger.warning('Encountered unhandled dirty IR statement: ' + stmt.cee.name)
			elif isinstance(stmt, pyvex.stmt.Exit):
				if stmt.jumpkind != ir.JumpKind.MapFail:
					self.registers.modified.add(ir.IRRegister.from_ir_stmt_exit(arch, stmt, ir_tyenv))
			elif isinstance(stmt, pyvex.stmt.IMark):
				pass
			elif isinstance(stmt, pyvex.stmt.NoOp):
				pass
			elif isinstance(stmt, pyvex.stmt.Put):
				self.registers.modified.add(ir.IRRegister.from_ir_stmt_put(arch, stmt, ir_tyenv))
			elif isinstance(stmt, pyvex.stmt.PutI):
				self.registers.modified.add(ir.IRRegister.from_ir_stmt_puti(arch, stmt, ir_tyenv))
			elif isinstance(stmt, pyvex.stmt.Store):
				if isinstance(stmt.data, pyvex.expr.Const):
					pass
				elif isinstance(stmt.data, pyvex.expr.RdTmp):
					self.registers.stored.update(taint_tracking[stmt.data.tmp])
				else:
					raise TaintTrackingError('can not handle Store where data is not Const or RdTmp')
			elif isinstance(stmt, pyvex.stmt.WrTmp):
				# implement taint-tracking to determine which registers were include in the calculation of
				# a value
				if isinstance(stmt.data, pyvex.expr.Get):
					register = ir.IRRegister.from_ir_expr_get(arch, stmt.data, ir_tyenv)
					self.registers.accessed.add(register)
					taint_tracking[stmt.tmp] = set((register,))
				elif isinstance(stmt.data, pyvex.expr.GetI):
					register = ir.IRRegister.from_ir_expr_geti(arch, stmt.data, ir_tyenv)
					self.registers.accessed.add(register)
					taint_tracking[stmt.tmp] = set((register,))
				else:
					tainted = set()
					for arg in getattr(stmt.data, 'args', []):
						if not isinstance(arg, pyvex.expr.RdTmp):
							continue
						tainted.update(taint_tracking[arg.tmp])
					taint_tracking[stmt.tmp] = tainted
			else:
				raise TaintTrackingError('unsupported IR statement: ' + stmt.__class__.__name__)
		for postprocessor in postprocessors[self.arch.name]:
			postprocessor(self)

	def __bytes__(self):
		return bytes(self.cs_instruction.bytes)

	def __eq__(self, other):
		return hash(self) == hash(other)

	def __hash__(self):
		return hash((bytes(self), self.address, (self.arch.name, self.arch.bits, self.arch.memory_endness), hash(self._ir_tyenv)))

	def __repr__(self):
		return "<{0} arch: {1}, at: 0x{2:04x} {3!r} >".format(self.__class__.__name__, self.arch.name, self.address,
															  self.source)

	def _fixup_vex_stmts(self, vex_statements):
		# pyvex adds a WrTmp statement to the end loading the instruction pointer into a
		# variable, this operation isn't useful for our purposes and affects the taint tracking
		last_stmt = vex_statements[-1]
		if isinstance(last_stmt, pyvex.stmt.WrTmp):
			vex_statements.pop()
			last_stmt = vex_statements[-1]

		# this fixes up the IR statements to remove natural increments to the instruction pointer to
		# prevent it from showing up while performing taint-tracking
		ins_ptr = ir.IRRegister.from_arch(self.arch, 'ip')  # get the instruction-pointer register
		if not isinstance(last_stmt, (pyvex.stmt.Put, pyvex.stmt.PutI)):
			return vex_statements
		if ir.IRRegister.from_ir_stmt_put(self.arch, last_stmt, self._ir_tyenv) != ins_ptr:
			return vex_statements
		if not isinstance(last_stmt.data, pyvex.expr.Const):
			return vex_statements
		if last_stmt.data.con.value == self.address + self.cs_instruction.size:
			vex_statements.pop()
		return vex_statements

	@property
	def address(self):
		return self.cs_instruction.address

	@property
	def bytes(self):
		return bytes(self)

	@property
	def bytes_hex(self):
		return binascii.b2a_hex(bytes(self)).decode('utf-8')

	@classmethod
	def from_bytes(cls, blob, arch, base=0x1000):
		cs_ins = next(arch.capstone.disasm(blob, base))
		irsb = ir.lift(blob, base, arch)
		vex_instructions = ir.irsb_to_instructions(irsb)
		vex_statements = vex_instructions[base]
		return cls(arch, cs_ins, vex_statements, irsb.tyenv)

	@classmethod
	def from_source(cls, source, arch, base=0x1000):
		blob, _ = arch.keystone.asm(utilities.remove_comments(source), base)
		return cls.from_bytes(bytes(blob), arch, base=base)

	def pp_asm(self, stream='stdout'):
		formatted = "0x{:04x}  {} {}".format(self.address, self.bytes_hex, self.source)
		if stream is not None:
			if isinstance(stream, str) and stream.lower() in ('stderr', 'stdout'):
				stream = getattr(sys, stream.lower())
			print(formatted, file=stream)
		return formatted

	def pp_ir(self, stream='stdout'):
		formatted = collections.deque()
		for stmt in self.vex_statements:
			if isinstance(stmt, pyvex.stmt.Put):
				reg_name = self.arch.translate_register_name(stmt.offset, stmt.data.result_size(self._ir_tyenv) // self.arch.byte_width)
				stmt_str = stmt.__str__(reg_name=reg_name)
			elif isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Get):
				reg_name = self.arch.translate_register_name(stmt.data.offset, stmt.data.result_size(self._ir_tyenv) // self.arch.byte_width)
				stmt_str = stmt.__str__(reg_name=reg_name)
			elif isinstance(stmt, pyvex.stmt.Exit):
				reg_name = self.arch.translate_register_name(stmt.offsIP, self.arch.bits // self.arch.byte_width)
				stmt_str = stmt.__str__(reg_name=reg_name)
			else:
				stmt_str = stmt.__str__()
			formatted.append(stmt_str)
		formatted = '\n'.join(formatted)
		if stream is not None:
			if isinstance(stream, str) and stream.lower() in ('stderr', 'stdout'):
				stream = getattr(sys, stream.lower())
			print(formatted, file=stream)
		return formatted

	@property
	def source(self):
		return "{0} {1}".format(self.cs_instruction.mnemonic, self.cs_instruction.op_str).strip()

	def to_irsb(self):
		return ir.lift(self.bytes, self.address, self.arch)

################################################################################
# Architecture Specific Post-Processors
################################################################################
amd64 = archinfo.ArchAMD64()
x86 = archinfo.ArchX86()

# FPU instructions record the Instruction Pointer, see section 8.1.8 of the Intel 64 and IA-32 Architectures
# Software Developer's Manual

# todo: this needs to account for additional x87 instructions accessing the instruction pointer
# this should also mark a registers as being modified since the instruction pointer is copied into it, but
# archinfo.ArchX86 does not seem to have floating-point instruction and data pointer registers
@register_postprocessor(amd64, x86, mnemonic=('fadd', 'faddp', 'fiadd'))
def x87_fpu_add(ins):
	ins.registers.accessed.add(ir.IRRegister.from_arch(ins.arch, 'ip'))

@register_postprocessor(amd64, x86, mnemonic=('fdiv', 'fdivp', 'fidiv'))
def x87_fpu_div(ins):
	ins.registers.accessed.add(ir.IRRegister.from_arch(ins.arch, 'ip'))

@register_postprocessor(amd64, x86, mnemonic=('fld',))
def x87_fpu_load(ins):
	ins.registers.accessed.add(ir.IRRegister.from_arch(ins.arch, 'ip'))

@register_postprocessor(amd64, x86, byte_mask='11011001 11101###')
def x87_fpu_load_constant(ins):
	ins.registers.accessed.add(ir.IRRegister.from_arch(ins.arch, 'ip'))

@register_postprocessor(amd64, x86, mnemonic=('fmul', 'fmulp', 'fimul'))
def x87_fpu_mul(ins):
	ins.registers.accessed.add(ir.IRRegister.from_arch(ins.arch, 'ip'))

@register_postprocessor(amd64, x86, mnemonic=('fsub', 'fsubp', 'fisub'))
def x87_fpu_sub(ins):
	ins.registers.accessed.add(ir.IRRegister.from_arch(ins.arch, 'ip'))
