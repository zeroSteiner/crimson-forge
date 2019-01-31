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
import collections
import functools
import logging
import random
import re

import crimson_forge.ir as ir
import crimson_forge.instruction as instruction

import archinfo
import boltons.iterutils

logger = logging.getLogger('crimson-forge.tailor')

_SIZES = {64: 'qword', 32: 'dword', 16: 'word', 8: 'byte'}

alterations = collections.defaultdict(list)
def register_alteration():
	def decorator(Alteration):
		@functools.wraps(Alteration.run)
		def wrapper(graph, arch):
			logger.info("Using %s alteration: %s", arch.name, Alteration.name)
			alteration = Alteration(arch)
			return alteration.run(graph)
		for arch in Alteration.architectures:
			alterations[arch.name].append(wrapper)
		return wrapper
	return decorator

def alter(graph, arch, modifier=1.0, iterations=1):
	if arch.name not in alterations:
		raise NotImplementedError('No alterations implemented for arch: ' + arch.name)
	while iterations > 0:
		for alteration in alterations[arch.name]:
			if random.random() > modifier:
				continue
			graph = alteration(graph, arch) or graph
		iterations -= 1
	return graph

class AlterationBase(object):
	architectures = ()
	modifies_size = True
	name = 'unknown'
	def __init__(self, arch):
		self.arch = arch

	def run(self, graph):
		raise NotImplementedError()

	def inject_instructions(self, graph, orig_ins, new_instructions):
		for predecessor in tuple(graph.predecessors(orig_ins)):
			graph.remove_edge(predecessor, orig_ins)
			graph.add_edge(predecessor, new_instructions[0])
		for successor in tuple(graph.successors(orig_ins)):
			graph.remove_edge(orig_ins, successor)
			graph.add_edge(new_instructions[-1], successor)
		for ins in new_instructions:
			graph.add_node(ins)
		for predecessor, successor in boltons.iterutils.pairwise(new_instructions):
			graph.add_edge(predecessor, successor)
		graph.remove_node(orig_ins)

	def ins_mov_ptr_val(self, register, value, address):
		size = _SIZES.get(register.width)
		if size is None:
			raise ValueError("Unknown size of register: {!r}".format(register))
		if isinstance(value, int):
			value = "0x{:x}".format(value)
		source = "mov {} ptr [{}], {}".format(size, register.name, value)
		return instruction.Instruction.from_source(source, self.arch, address)

################################################################################
# Architecture Specific Alterations
################################################################################
amd64 = archinfo.ArchAMD64()
x86 = archinfo.ArchX86()

#@register_alteration()
class PushValue(AlterationBase):
	architectures = (amd64, x86)
	name = 'push_value'
	def run(self, graph):
		stk_ptr = ir.IRRegister.from_arch(self.arch, 'sp')
		for ins in tuple(graph.nodes):
			match = re.match(r'^push (?P<value>\S+)', ins.source)
			if match is None:
				continue
			self.inject_instructions(graph, ins, (
				instruction.Instruction.from_source("sub {}, {}".format(stk_ptr.name, stk_ptr.width // 8), self.arch, ins.address),
				self.ins_mov_ptr_val(stk_ptr, match.group('value'), ins.address)
			))

@register_alteration()
class MoveConstant(AlterationBase):
	architectures = (amd64, x86)
	name = 'move_constant'
	def run(self, graph):
		stk_ptr = ir.IRRegister.from_arch(self.arch, 'sp')
		for ins in tuple(graph.nodes):
			match = re.match(r'^mov (?P<register>\S+), 0x(?P<value>[a-f0-9]+)', ins.source)
			if match is None:
				continue
			reg = ir.IRRegister.from_arch(self.arch, match.group('register'))
			if reg & stk_ptr:
				continue
			value = int(match.group('value'), 16)
			mod = 0
			value -= mod
			self.inject_instructions(graph, ins, (
				instruction.Instruction.from_source("mov {}, 0x{:x}".format(reg.name, value), self.arch, ins.address),
				instruction.Instruction.from_source("add {}, 0x{:x}".format(reg.name, mod), self.arch, ins.address)
			))
