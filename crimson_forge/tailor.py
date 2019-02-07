#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  crimson_forge/tailor.py
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

# tailors make alterations so that's what we're going to do here
import ast
import collections
import functools
import logging
import random
import re
import struct

import crimson_forge.ir as ir
import crimson_forge.instruction as instruction

import archinfo
import boltons.iterutils

logger = logging.getLogger('crimson-forge.tailor')

_SIZES = {64: 'qword', 32: 'dword', 16: 'word', 8: 'byte'}

def is_numeric(string):
	return re.match(r'^(0x[a-f0-9]+|[0-9]+)$', string, flags=re.IGNORECASE) is not None

alterations = collections.defaultdict(list)
def register_alteration():
	def decorator(Alteration):
		@functools.wraps(Alteration.run)
		def wrapper(block, graph):
			arch = block.arch
			logger.info("Using %s alteration: %s", arch.name, Alteration.name)
			alteration = Alteration(arch)
			return alteration.run(block, graph)
		for arch in Alteration.architectures:
			alterations[arch.name].append(wrapper)
		return wrapper
	return decorator

def alter(block, modifier=1.0, iterations=1):
	arch = block.arch
	graph = block.to_digraph()
	if arch.name not in alterations:
		raise NotImplementedError('No alterations implemented for arch: ' + arch.name)
	while iterations > 0:
		for alteration in alterations[arch.name]:
			if random.random() > modifier:
				continue
			graph = alteration(block, graph) or graph
		iterations -= 1
	return graph

def _resub_relative_address(match, address=0):
	value = ast.literal_eval(match.group('offset')[1:])
	value += address
	return " 0x{:x}".format(value)

class AlterationBase(object):
	architectures = ()
	modifies_size = True
	name = 'unknown'
	_regex_relative = re.compile('\s(?P<offset>\$[+-](0x[a-f0-9]+|[0-9]+))(?=\s|;|$)')
	def __init__(self, arch):
		self.arch = arch

	def check_instruction(self, ins):
		raise NotImplementedError()

	def check(self, graph):
		return any(self.check_instruction(ins) for ins in graph.nodes)

	def run(self, graph):
		raise NotImplementedError()

	def inject_instructions(self, graph, orig_ins, new_instructions):
		instructions = collections.deque()
		for new_ins in new_instructions:
			if isinstance(new_ins, str):
				new_ins = self._regex_relative.sub(functools.partial(_resub_relative_address, address=orig_ins.address), new_ins)
				new_ins = instruction.Instruction.from_source(new_ins, self.arch, orig_ins.address)
			elif not isinstance(new_ins, instruction.Instruction):
				raise TypeError('new instruction must be str or Instruction instance')
			instructions.append(new_ins)
		for predecessor in tuple(graph.predecessors(orig_ins)):
			graph.remove_edge(predecessor, orig_ins)
			graph.add_edge(predecessor, instructions[0])
		for successor in tuple(graph.successors(orig_ins)):
			graph.remove_edge(orig_ins, successor)
			graph.add_edge(instructions[-1], successor)
		for ins in instructions:
			graph.add_node(ins)
		for predecessor, successor in boltons.iterutils.pairwise(instructions):
			graph.add_edge(predecessor, successor)
		graph.remove_node(orig_ins)
		return instructions

	# write to a pointer
	def ins_mov_ptr_val(self, register, value, width=None):
		if register.width != self.arch.bits:
			raise ValueError('Register is not a native size for the architecture')
		size = _SIZES.get(width or self.arch.bits)
		if size is None:
			raise ValueError("Unknown size of register: {!r}".format(register))
		if isinstance(value, int):
			value = "0x{:x}".format(value)
		return "mov {} ptr [{}], {}".format(size, register.name, value)

	# read from a pointer
	def ins_mov_val_ptr(self, register, value, width=None):
		if register.width != self.arch.bits:
			raise ValueError('Register is not a native size for the architecture')
		size = _SIZES.get(width or self.arch.bits)
		if size is None:
			raise ValueError("Unknown size of register: {!r}".format(register))
		if isinstance(value, int):
			value = "0x{:x}".format(value)
		return "mov {}, {} ptr [{}]".format(value, size, register.name)

################################################################################
# Architecture Specific Alterations
################################################################################
amd64 = archinfo.ArchAMD64()
x86 = archinfo.ArchX86()

def _re_match(regex, ins):
	regex += r'(\s+;.*)?$'
	return re.match(regex, ins.source, flags=re.IGNORECASE)

@register_alteration()
class PushValue(AlterationBase):
	architectures = (amd64, x86)
	name = 'push_value'
	def run(self, block, graph):
		stk_ptr = ir.IRRegister.from_arch(self.arch, 'sp')
		for ins in tuple(graph.nodes):
			match = re.match(r'^push (?P<value>\S+)', ins.source)
			if match is None:
				continue
			if not is_numeric(match.group('value')):
				if stk_ptr & ir.IRRegister.from_arch(self.arch, match.group('value')):
					continue
			self.inject_instructions(graph, ins, (
				"sub {}, {}".format(stk_ptr.name, stk_ptr.width // 8),
				self.ins_mov_ptr_val(stk_ptr, match.group('value'))
			))

@register_alteration()
class PopValue(AlterationBase):
	architectures = (amd64, x86)
	name = 'pop_value'
	def run(self, block, graph):
		stk_ptr = ir.IRRegister.from_arch(self.arch, 'sp')
		for ins in tuple(graph.nodes):
			match = re.match(r'^pop (?P<value>\S+)', ins.source)
			if match is None:
				continue
			if stk_ptr & ir.IRRegister.from_arch(self.arch, match.group('value')):
				continue
			self.inject_instructions(graph, ins, (
				self.ins_mov_val_ptr(stk_ptr, match.group('value')),
				"add {}, {}".format(stk_ptr.name, stk_ptr.width // 8)
			))

@register_alteration()
class MoveConstant(AlterationBase):
	architectures = (amd64, x86)
	name = 'move_constant'
	def run(self, block, graph):
		stk_ptr = ir.IRRegister.from_arch(self.arch, 'sp')
		for ins in tuple(graph.nodes):
			match = re.match(r'^mov (?P<register>\S+), 0x(?P<value>[a-f0-9]+)', ins.source)
			if match is None:
				continue
			reg = ir.IRRegister.from_arch(self.arch, match.group('register'))
			if stk_ptr & reg:
				continue
			value = int(match.group('value'), 16)
			modifier = random.randint(0, value)
			value -= modifier
			self.inject_instructions(graph, ins, (
				"mov {}, 0x{:x}".format(reg.name, value),
				"add {}, 0x{:x}".format(reg.name, modifier)
			))

@register_alteration()
class ReplaceJCXZ(AlterationBase):
	architectures = (amd64, x86)
	name = 'replace_jcxz'
	def run(self, block, graph):
		ins = tuple(graph.nodes)[-1]
		match = _re_match(r'^(?P<jump>j[er]?cxz) 0x(?P<value>[a-f0-9]+)', ins)
		if match is None:
			return
		value = int(match.group('value'), 16)
		# keystone doesn't have a way for us to create a jmp instruction of a deterministic size so we create an
		# Instruction instance from bytes manually to ensure it's always 5 bytes long
		new_opcode = b'\xe9' + struct.pack('<i', value - ins.address - 5)
		ins_1, ins_2, ins_3, = self.inject_instructions(graph, ins, (
			"{} $+4".format(match.group('jump')),
			"jmp $+7",
			instruction.Instruction.from_bytes(new_opcode, self.arch, base=ins.address)
		))
		ins_1.jmp_reference = instruction.Reference(instruction.ReferenceType.INSTRUCTION, ins_3)
		ins_2.jmp_reference = instruction.Reference(instruction.ReferenceType.BLOCK, block.children[block.next_address])
