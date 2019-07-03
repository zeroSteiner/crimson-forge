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
import crimson_forge.source as source

import archinfo
import boltons.iterutils

logger = logging.getLogger('crimson-forge.tailor')

_SIZES = {64: 'qword', 32: 'dword', 16: 'word', 8: 'byte'}

class SelectorLinear(object):
	def __init__(self, rate):
		if rate == 0 or rate == 1:
			rate = float(rate)
		if not isinstance(rate, float):
			raise TypeError('rate must be a float between 0.0 and 1.0')
		if rate <= 0.0 or rate >= 1.0:
			raise TypeError('rate must be a float between 0.0 and 1.0')
		self.rate = rate

	def seed(self, iterations):
		for iteration in range(iterations):
			self.select()

	def select(self):
		return random.random() < self.rate

class SelectorExponentialGrowth(SelectorLinear):
	def __init__(self, *args, **kwargs):
		super(SelectorExponentialGrowth, self).__init__(*args, **kwargs)
		self.base_rate = self.rate
		self.streak = 0

	def select(self):
		selected = super(SelectorExponentialGrowth, self).select()
		if selected:
			self.streak = 0
			self.rate = self.base_rate
		else:
			self.streak += 1
			self.rate += 1 - (1 - self.base_rate) ** (self.streak + 1)
		return selected

def _is_numeric(string):
	return re.match(r'^(0x[a-f0-9]+|[0-9]+)$', string, flags=re.IGNORECASE) is not None

def _re_match(regex, ins):
	# this will automatically append source.REGEX_INSTRUCTION_END to terminate the
	# instruction, ensuring that *regex* is the entire instruction
	regex += source.REGEX_INSTRUCTION_END
	return re.match(regex, ins.source, flags=re.IGNORECASE)

def _resub_relative_address(match, address=0):
	value = ast.literal_eval(match.group('offset')[1:])
	value += address
	return " 0x{:x}".format(value)

alterations = collections.defaultdict(list)
def register_alteration():
	def decorator(alteration_class):
		for arch in alteration_class.architectures:
			alteration = alteration_class(arch)
			alterations[arch.name].append(alteration)
		return alteration_class
	return decorator

class AlterationsEngine(object):
	def __init__(self, arch, rate=0.5):
		if arch.name not in alterations:
			raise NotImplementedError('No alterations implemented for arch: ' + arch.name)
		self.arch = arch
		self.selector = SelectorLinear(rate)

	def apply(self, graph, patches=True):
		for ins in tuple(graph.nodes):
			usable_alterations = tuple(alteration for alteration in alterations[self.arch.name] if alteration.check_instruction(ins))
			if not usable_alterations:
				continue
			selected_alteration = None
			if patches:
				patch_alterations = tuple(alteration for alteration in usable_alterations if alteration.is_patch)
				if patch_alterations:
					if len(patch_alterations) > 1:
						raise RuntimeError('more than one patch alteration to be applied')
					selected_alteration = patch_alterations[0]
			if selected_alteration is None:
				if not self.selector.select():
					continue
				selected_alteration = random.choice(usable_alterations)
			logger.debug("Using %s alteration: %s", graph.arch.name, selected_alteration.name)
			graph = selected_alteration.run(graph, ins) or graph
		return graph

class AlterationBase(object):
	architectures = ()
	modifies_size = True
	name = 'unknown'
	is_patch = False
	_regex_relative = re.compile('\s(?P<offset>\$[+-](0x[a-f0-9]+|[0-9]+))(?=\s|;|$)')
	def __init__(self, arch):
		self.arch = arch
		self.reg_ip = ir.IRRegister.from_arch(self.arch, 'ip')
		self.reg_sp = ir.IRRegister.from_arch(self.arch, 'sp')

	def check_instruction(self, ins):
		raise NotImplementedError()

	def run(self, graph, run):
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

@register_alteration()
class PushValue(AlterationBase):
	architectures = (amd64, x86)
	name = 'push_value'
	def check_instruction(self, ins):
		match = _re_match(r'^push (?P<value>\S+)', ins)
		if match is None:
			return False
		if not _is_numeric(match.group('value')):
			if self.reg_sp & ir.IRRegister.from_arch(self.arch, match.group('value')):
				return False
		return match

	def run(self, graph, ins):
		match = self.check_instruction(ins)
		if not match:
			return
		self.inject_instructions(graph, ins, (
			"sub {}, {}".format(self.reg_sp.name, self.reg_sp.width // 8),
			self.ins_mov_ptr_val(self.reg_sp, match.group('value'))
		))

@register_alteration()
class PopValue(AlterationBase):
	architectures = (amd64, x86)
	name = 'pop_value'
	def check_instruction(self, ins):
		match = _re_match(r'^pop (?P<value>\S+)', ins)
		if match is None:
			return False
		if self.reg_sp & ir.IRRegister.from_arch(self.arch, match.group('value')):
			return False
		return match

	def run(self, graph, ins):
		match = self.check_instruction(ins)
		if not match:
			return
		self.inject_instructions(graph, ins, (
			self.ins_mov_val_ptr(self.reg_sp, match.group('value')),
			"add {}, {}".format(self.reg_sp.name, self.reg_sp.width // 8)
		))

@register_alteration()
class ConstantAdd(AlterationBase):
	architectures = (amd64, x86)
	name = 'constant_add'
	def check_instruction(self, ins):
		match = _re_match(r'^add (?P<register>\S+), 0x(?P<value>[a-f0-9]+)', ins)
		if match is None:
			return False
		if self.reg_sp & ir.IRRegister.from_arch(self.arch, match.group('register')):
			return False
		value = int(match.group('value'), 16)
		if value < 2:
			return False
		return match

	def run(self, graph, ins):
		match = self.check_instruction(ins)
		if not match:
			return
		reg = ir.IRRegister.from_arch(self.arch, match.group('register'))
		value = int(match.group('value'), 16)
		modifier = random.randint(0, value)
		self.inject_instructions(graph, ins, (
			"add {}, 0x{:x}".format(reg.name, value - modifier),
			"add {}, 0x{:x}".format(reg.name, modifier)
		))

@register_alteration()
class ConstantMove(AlterationBase):
	architectures = (amd64, x86)
	name = 'constant_move'
	def check_instruction(self, ins):
		match = _re_match(r'^mov (?P<register>\S+), 0x(?P<value>[a-f0-9]+)', ins)
		if match is None:
			return False
		if self.reg_sp & ir.IRRegister.from_arch(self.arch, match.group('register')):
			return False
		value = int(match.group('value'), 16)
		if value < 2:
			return False
		return match

	def run(self, graph, ins):
		match = self.check_instruction(ins)
		if not match:
			return
		reg = ir.IRRegister.from_arch(self.arch, match.group('register'))
		value = int(match.group('value'), 16)
		modifier = random.randint(0, value)
		self.inject_instructions(graph, ins, (
			"mov {}, 0x{:x}".format(reg.name, value - modifier),
			"add {}, 0x{:x}".format(reg.name, modifier)
		))

@register_alteration()
class ConstantSubtract(AlterationBase):
	architectures = (amd64, x86)
	name = 'constant_subtract'
	def check_instruction(self, ins):
		match = _re_match(r'^sub (?P<register>\S+), 0x(?P<value>[a-f0-9]+)', ins)
		if match is None:
			return False
		if self.reg_sp & ir.IRRegister.from_arch(self.arch, match.group('register')):
			return False
		value = int(match.group('value'), 16)
		if value < 2:
			return False
		return match

	def run(self, graph, ins):
		match = self.check_instruction(ins)
		if not match:
			return
		reg = ir.IRRegister.from_arch(self.arch, match.group('register'))
		value = int(match.group('value'), 16)
		modifier = random.randint(0, value)
		self.inject_instructions(graph, ins, (
			"sub {}, 0x{:x}".format(reg.name, value - modifier),
			"sub {}, 0x{:x}".format(reg.name, modifier)
		))

@register_alteration()
class PatchJCXZ(AlterationBase):
	architectures = (amd64, x86)
	name = 'patch_jcxz'
	is_patch = True
	def check_instruction(self, ins):
		match = _re_match(r'^(?P<jump>j[er]?cxz) 0x(?P<value>[a-f0-9]+)', ins)
		if match is None:
			return False
		return match

	def run(self, graph, ins):
		match = self.check_instruction(ins)
		if not match:
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
		ins_2.jmp_reference = instruction.Reference(instruction.ReferenceType.BLOCK_ADDRESS, ins.next_address)
