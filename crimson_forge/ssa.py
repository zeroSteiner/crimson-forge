#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  crimson_forge/ssa.py
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

import collections.abc

import crimson_forge.ir as ir

VARIABLE_REGISTERS = {
	'AMD64': (
		'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi',
		'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'
	),
	'X86': (
		'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'
	),
}

# hashable, immutable
class Variable(object):
	__slots__ = ('__defined_at', '__register')
	def __init__(self, defined_at, register):
		self.__defined_at = defined_at
		self.__register = register

	def __hash__(self):
		return hash((self.__defined_at, self.__register))

	def __repr__(self):
		return "<{} name: {!r} >".format(self.__class__.__name__, self.name)

	@property
	def name(self):
		return "var_{}_{:04x}".format(self.__register.name, self.__defined_at)

	@property
	def register(self):
		return self.__register

class Variables(collections.abc.Collection):
	def __init__(self, instructions):
		self._storage = []
		arch = instructions.arch
		if arch.name not in VARIABLE_REGISTERS:
			raise NotImplementedError('SSA Variables is not implemented for arch: ' + arch.name)
		var_regs = tuple(ir.IRRegister.from_arch(arch, name) for name in VARIABLE_REGISTERS[arch.name])
		for ins in instructions.values():
			for reg in ins.registers.modified:
				var_reg = next((var_reg for var_reg in var_regs if var_reg * reg), None)
				if var_reg is None:
					continue
				self._storage.append(Variable(ins.address, var_reg))

	def __contains__(self, item):
		return item in self._storage

	def __iter__(self):
		yield from self._storage

	def __len__(self):
		return len(self._storage)
