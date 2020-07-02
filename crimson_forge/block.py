#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  crimson_forge/block.py
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
import collections.abc
import itertools
import logging
import random

import crimson_forge.assembler as assembler
import crimson_forge.base as base
import crimson_forge.ir as ir
import crimson_forge.source as source
import crimson_forge.ssa as ssa

logger = logging.getLogger('crimson-forge.basic-block')

def _path_choice_iterator(choices):
	for choice in sorted(choices, key=lambda ins: ins.address):
		choices.remove(choice)
		yield choice
		choices.add(choice)

def _path_recursor(constraints, selection, choices, current_path=None):
	all_paths = collections.deque()
	if current_path is None:
		current_path = collections.deque()
	current_path.append(selection)
	# analyze the nodes which are successors (dependants) of the selection
	for successor in constraints.successors(selection):
		# skip the node if it's already been added
		if successor in current_path:
			continue
		# or if all of it's predecessors (dependencies) have not been met
		if not all(predecessor in current_path for predecessor in constraints.predecessors(successor)):
			continue
		choices.add(successor)
	if choices:
		for choice in _path_choice_iterator(choices):
			all_paths.extend(_path_recursor(constraints, choice, choices.copy(), current_path=current_path))
	else:
		all_paths.append(current_path.copy())
	current_path.pop()
	return all_paths

def path_permutations(constraints):
	# the initial choices are any node without a predecessor (dependency)
	choices = set(node for node in constraints.nodes if len(tuple(constraints.predecessors(node))) == 0)
	all_paths = collections.deque()
	for choice in _path_choice_iterator(choices):
		all_paths.extend(_path_recursor(constraints, choice, choices.copy()))
	return all_paths

class _InstructionsProxy(base.InstructionsProxy):
	def __init__(self, arch, cs_instructions, vex_ins, ir_tyenv):
		super(_InstructionsProxy, self).__init__(arch, cs_instructions)
		self._vex_instructions = vex_ins
		self._ir_tyenv = ir_tyenv

	def _resolve_ir(self, address):
		return self._vex_instructions[address], self._ir_tyenv

class BlockBase(base.Base):  # yo dawg I head you like base classes
	def source_iter(self):
		raise NotImplementedError()

class DataBlock(BlockBase):
	def __repr__(self):
		return "<{} arch: {}, at: 0x{:04x}, size: {}, data: {!r} >".format(self.__class__.__name__, self.arch.name, self.address, self.size, self.bytes)

	def source_iter(self):
		yield from source.raw_bytes(self.bytes)

class InstructionsDiGraph(base.DiGraphBase):
	"""
	A directed graph plotting individual instructions within a basic block based
	on their positional constraints.
	"""
	def __init__(self, instructions, *args, **kwargs):
		"""
		:param instructions: The instructions to include in this graph.
		"""
		super(InstructionsDiGraph, self).__init__(*args, **kwargs)
		self._instructions = instructions
		t_instructions = tuple(self._instructions.values())

		self.add_nodes_from(t_instructions)
		ins_ptr = ir.IRRegister.from_arch(self.arch, 'ip')

		constraints = collections.defaultdict(collections.deque)
		for idx, ins in enumerate(t_instructions):
			for reg in (ins.registers.accessed | ins.registers.stored):
				# for each accessed register, we search backwards to find when it was set
				for pos in reversed(range(0, idx)):
					o_ins = t_instructions[pos]
					if reg == ins_ptr:
						# if the instruction pointer is accessed or stored then this instruction is positionally
						# dependant, so mark all proceeding instructions as dependants so the position is correct
						constraints[ins].append(o_ins)
					elif o_ins.dirty or reg.in_iterable(o_ins.registers.modified):
						constraints[ins].append(o_ins)
						break

				for pos in range(idx + 1, len(t_instructions)):
					o_ins = t_instructions[pos]
					if reg == ins_ptr:
						constraints[o_ins].append(ins)
					elif o_ins.dirty or reg.in_iterable(o_ins.registers.modified):
						constraints[o_ins].append(ins)
						break

		parent_nodes = set(itertools.chain(*constraints.values()))
		leaf_nodes = set(ins for ins in self._instructions.values() if ins not in parent_nodes)

		exit_node = next((ins for ins in leaf_nodes if ins_ptr in ins.registers.modified), None)
		if exit_node is not None:
			leaf_nodes.remove(exit_node)
			for leaf_node in leaf_nodes:
				constraints[self._exit_for_leaf(leaf_node, exit_node)].append(leaf_node)

		for child, dependencies in constraints.items():
			for parent in dependencies:
				self.add_edge(parent, child)

	def _exit_for_leaf(self, leaf_node, exit_node):
		t_instructions = tuple(self._instructions.values())
		if t_instructions[-1] != exit_node:
			# this basic-block is corrupted, the instructions continue past an
			# explicit modification to the instruction pointer such as a call or
			# jump
			raise ValueError('the exit node was not identified as the last instruction')
		for ins in reversed(t_instructions):
			if ins == leaf_node:
				break
			if not any(reg.in_iterable(ins.registers.accessed | ins.registers.stored) for reg in leaf_node.registers.modified):
				return ins
		return exit_node

	@property
	def arch(self):
		return self._instructions.arch

	def _graphml_id(self, ins):
		return "instr[0x{:04x}]".format(ins.address)

	def _graphml_node_attributes(self, ins):
		return {'address': "0x{:04x}".format(ins.address), 'instr.source': ins.source, 'instr.hex': ins.bytes_hex}

	def _graphviz_name(self, ins):
		return "0x{:04x}".format(ins.address)

	def _graphviz_node_kwargs(self, ins):
		label = "0x{0:04x} {1}".format(ins.address, ins.source)
		return dict(label=label)

	def to_instructions(self):
		instructions = collections.deque()
		# the initial choices are any node without a predecessor (dependency)
		choices = set(node for node in self.nodes if len(tuple(self.predecessors(node))) == 0)
		while choices:  # continue to make selections while we have choices
			selection = random.choice(tuple(choices))  # make a selection
			choices.remove(selection)
			instructions.append(selection)
			# analyze the nodes which are successors (dependants) of the selection
			for successor in self.successors(selection):
				# skip the node if it's already been added
				if successor in instructions:
					continue
				# or if all of it's predecessors (dependencies) have not been met
				if not all(predecessor in instructions for predecessor in self.predecessors(successor)):
					continue
				choices.add(successor)
		return instructions

class BasicBlock(BlockBase):
	def __init__(self, blob, arch, address, cs_instructions, vex_instructions, ir_tyenv, ir_jumpkind):
		super(BasicBlock, self).__init__(blob, arch, address)
		self.cs_instructions.update(cs_instructions)
		self.vex_instructions.update(vex_instructions)
		self.parents = {}
		self.children = {}
		self.ir_tyenv = ir_tyenv
		self.ir_jumpkind = ir_jumpkind
		self.instructions = _InstructionsProxy(arch, self.cs_instructions, self.vex_instructions, ir_tyenv)

	def __repr__(self):
		return "<{} arch: {}, at: 0x{:04x}, size: {}, jump: {} >".format(self.__class__.__name__, self.arch.name, self.address, self.size, self.ir_jumpkind)

	def _split_new(self, addresses, ir_jumpkind):
		cls = self.__class__
		blob_start = addresses[0] - self.address
		blob_end = (addresses[-1] - self.address) + self.cs_instructions[addresses[-1]].size
		blob = self.bytes[blob_start:blob_end]
		cs_ins = collections.OrderedDict((a, self.cs_instructions[a]) for a in addresses)
		vex_ins = collections.OrderedDict((a, self.vex_instructions[a]) for a in addresses)
		return cls(blob, self.arch, addresses[0], cs_ins, vex_ins, self.ir_tyenv, ir_jumpkind)

	def connect_to(self, child):
		if len(self.children) == 2 and child.address not in self.children:
			raise RuntimeError('basic-block can not have more than two children')
		self.children[child.address] = child
		child.parents[self.address] = self

	def disconnect_from(self, child):
		if isinstance(child, BasicBlock):
			child = child.address
		child_bblock = self.children.pop(child)
		child_bblock.parents.pop(self.address)
		return child_bblock

	@classmethod
	def from_bytes(cls, blob, arch, base=0x1000):
		cs_instructions = collections.OrderedDict()
		cs_instructions.update((ins.address, ins) for ins in arch.capstone.disasm(blob, base))
		return cls.from_irsb(blob, cs_instructions, ir.lift(blob, base, arch))

	@classmethod
	def from_source(cls, text, arch, base=0x1000):
		blob = assembler.assemble_source(arch, text, base=base)
		return cls.from_bytes(blob, arch, base=base)

	@classmethod
	def from_irsb(cls, blob, cs_instructions, irsb):
		vex_instructions = ir.irsb_to_instructions(irsb)
		return cls(blob, irsb.arch, irsb.addr, cs_instructions, vex_instructions, ir_tyenv=irsb.tyenv, ir_jumpkind=irsb.jumpkind)

	def is_direct_child_of(self, address):
		if not address in self.children:
			return False
		last_address, last_instruction = tuple(self.cs_instructions.items())[-1]
		return last_address + last_instruction.size == address

	def is_direct_parent_of(self, address):
		parent = self.parents.get(address)
		if parent is None:
			return False
		return parent.is_direct_child_of(self.address)

	def permutation_count(self):
		constraints = self.to_digraph()
		all_permutations = path_permutations(constraints)
		return len(all_permutations)

	def split(self, address):
		# split this block at the specified address (which can not be the first address) into two,
		# this instance takes on the attributes of the lower block which maintains it's address while
		# a new block at the specified address is returned
		logger.info('Splitting basic-block 0x%04x at 0x%04x', self.address, address)
		addresses = tuple(self.cs_instructions.keys())
		index = addresses.index(address)
		if not index:
			raise ValueError('can not split on the first address')
		# build the new parent (block1) and child (block2) blocks
		block1 = self._split_new(addresses[:index], ir.JumpKind.Boring)
		block2 = self._split_new(addresses[index:], self.ir_jumpkind)

		# update this block to with the new parent information
		self.bytes = block1.bytes
		self.ir_jumpkind = block1.ir_jumpkind
		self.cs_instructions.clear()
		self.cs_instructions.update(block1.cs_instructions)
		self.vex_instructions.clear()
		self.vex_instructions.update(block1.vex_instructions)

		# update connected child relationships, because this block is updated in place,
		# it is not necessary to update connected parent relationships
		for child in self.children.values():
			# this is no longer the child's parent, block2 is
			child.parents.pop(self.address)
			block2.connect_to(child)
		self.children.clear()
		self.connect_to(block2)
		return block2

	@property
	def ssa_variables(self):
		return ssa.Variables(self.instructions)

	def to_data_block(self):
		for parent in tuple(self.parents.values()):
			parent.disconnect_from(self)
		for child in tuple(self.children.values()):
			self.disconnect_from(child)
		return DataBlock(self.bytes, self.arch, self.address)

	def to_digraph(self):
		graph = InstructionsDiGraph(self.instructions)
		return graph
