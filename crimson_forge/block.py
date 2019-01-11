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

import binascii
import collections
import collections.abc
import itertools
import random

import crimson_forge.ir as ir
import crimson_forge.utilities as utilities

import graphviz
import networkx
import networkx.algorithms
import pyvex

def _irsb_to_instructions(irsb):
	ir_instructions = collections.OrderedDict()
	for statement in irsb.statements:
		if isinstance(statement, pyvex.stmt.IMark):
			address = statement.addr
			ir_instructions[address] = collections.deque()
		ir_instructions[address].append(statement)
	return ir_instructions

_InstructionRegisters = collections.namedtuple('InstructionRegisters', ('accessed', 'modified', 'stored'))
# hashable
class Instruction(object):
	def __init__(self, arch, cs_ins, vex_statements, ir_tyenv):
		self.arch = arch
		self.cs_instruction = cs_ins
		self.vex_statements = vex_statements
		self._ir_tyenv = ir_tyenv

		self.registers = _InstructionRegisters(set(), set(), set())
		vex_statements = self._fixup_vex_stmts(vex_statements.copy())
		taint_tracking = {}
		for stmt in vex_statements:
			if isinstance(stmt, pyvex.stmt.Exit):
				self.registers.modified.add(ir.IRRegister.from_ir_stmt_exit(arch, stmt, ir_tyenv))
			elif isinstance(stmt, (pyvex.stmt.Put, pyvex.stmt.PutI)):
				self.registers.modified.add(ir.IRRegister.from_ir_stmt_put(arch, stmt, ir_tyenv))
			elif isinstance(stmt, pyvex.stmt.Store) and isinstance(stmt.data, pyvex.expr.RdTmp):
				self.registers.stored.update(taint_tracking[stmt.data.tmp])
			elif isinstance(stmt, pyvex.stmt.WrTmp):
				# implement taint-tracking to determine which registers were include in the calculation of
				# a value
				if isinstance(stmt.data, pyvex.expr.Get):
					register = ir.IRRegister.from_ir_expr_get(arch, stmt.data, ir_tyenv)
					self.registers.accessed.add(register)
					taint_tracking[stmt.tmp] = set((register,))
				else:
					tainted = set()
					for arg in getattr(stmt.data, 'args', []):
						if not isinstance(arg, pyvex.expr.RdTmp):
							continue
						tainted.update(taint_tracking[arg.tmp])
					taint_tracking[stmt.tmp] = tainted

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

	@property
	def source(self):
		return "{0} {1}".format(self.cs_instruction.mnemonic, self.cs_instruction.op_str).strip()

	# needs to come after
	def depends_on(self, ins):
		"""
		Check if the instruction instance, depends on the specified instruction
		*ins*. This instruction would be dependant if, for example *ins* loads a
		value which this instance depnds on.

		:param ins: The instruction to test for dependency status.
		:type ins: :py:class:`.Instruction`
		:return: ``True`` if this instruction depends on the other, otherwise ``False``.
		:rtype: bool
		"""
		# sanity checks
		if not isinstance(ins, Instruction):
			raise TypeError('ins must be an Instruction instance')
		if ins.address >= self.address:
			raise ValueError('ins.address >= self.address')
		if any(a_reg & r_mod for a_reg, r_mod in itertools.product(self.registers.accessed, ins.registers.modified)):
			return True
		if any(s_reg & r_mod for s_reg, r_mod in itertools.product(self.registers.stored, ins.registers.modified)):
			return True
		return False

	# needs to come before
	def dependant_of(self, ins):
		# sanity checks
		if not isinstance(ins, Instruction):
			raise TypeError('ins must be an Instruction instance')
		if ins.address <= self.address:
			raise ValueError('ins.address <= self.address')
		if any(a_reg & r_mod for a_reg, r_mod in itertools.product(self.registers.accessed, ins.registers.modified)):
			return True
		if any(s_reg & r_mod for s_reg, r_mod in itertools.product(self.registers.stored, ins.registers.modified)):
			return True
		return False

	@classmethod
	def from_bytes(cls, blob, arch, base=0x1000):
		cs_ins = next(arch.capstone.disasm(blob, base))
		irsb = ir.lift(blob, base, arch)
		vex_instructions = _irsb_to_instructions(irsb)
		vex_statements = vex_instructions[base]
		return cls(arch, cs_ins, vex_statements, irsb.tyenv)

	@classmethod
	def from_source(cls, source, arch, base=0x1000):
		blob, _ = arch.keystone.asm(utilities.remove_comments(source))
		return cls.from_bytes(bytes(blob), arch, base=base)


class _Instructions(collections.abc.Mapping):
	def __init__(self, arch, cs_ins, vex_ins, ir_tyenv):
		self.arch = arch
		self.cs_instructions = cs_ins
		self.vex_instructions = vex_ins
		self._ir_tyenv = ir_tyenv

	def __getitem__(self, key):
		ins = Instruction(
			self.arch,
			self.cs_instructions[key],
			self.vex_instructions[key],
			self._ir_tyenv
		)
		return ins

	def __iter__(self):
		yield from self.cs_instructions.keys()

	def __len__(self):
		return len(self.cs_instructions)

	def __repr__(self):
		return "<{0} arch: {1} >".format(self.__class__.__name__, self.arch.name)


class BasicBlock(utilities.Base):
	def __init__(self, blob, arch, address, cs_instructions, vex_instructions, ir_tyenv):
		super(BasicBlock, self).__init__(blob, arch, address)
		self.cs_instructions.update(cs_instructions)
		self.vex_instructions.update(vex_instructions)
		self.parents = {}
		self.children = {}
		self._ir_tyenv = ir_tyenv
		self.instructions = _Instructions(arch, self.cs_instructions, self.vex_instructions, ir_tyenv)

	def connect_to(self, child):
		self.children[child.address] = child
		child.parents[self.address] = self

	@classmethod
	def from_bytes(cls, blob, arch, base=0x1000):
		cs_instructions = collections.OrderedDict()
		cs_instructions.update((ins.address, ins) for ins in arch.capstone.disasm(blob, base))
		return cls.from_irsb(blob, cs_instructions, ir.lift(blob, base, arch))

	@classmethod
	def from_irsb(cls, blob, cs_instructions, irsb):
		vex_instructions = _irsb_to_instructions(irsb)
		return cls(blob, irsb.arch, irsb.addr, cs_instructions, vex_instructions, ir_tyenv=irsb.tyenv)

	def _split_new(self, addresses):
		cls = self.__class__
		blob_start = addresses[0] - self.address
		blob_end = (addresses[-1] - self.address) + self.cs_instructions[addresses[-1]].size
		blob = self.bytes[blob_start:blob_end]
		cs_ins = collections.OrderedDict((a, self.cs_instructions[a]) for a in addresses)
		vex_ins = collections.OrderedDict((a, self.vex_instructions[a]) for a in addresses)
		return cls(blob, self.arch, addresses[0], cs_ins, vex_ins, self._ir_tyenv)

	def split(self, address):
		# split this block at the specified address (which can not be the first address) into two,
		# this instance takes on the attributes of the lower block which maintains it's address while
		# a new block at the specified address is returned
		addresses = tuple(self.cs_instructions.keys())
		index = addresses.index(address)
		if not index:
			raise ValueError('can not split on the first address')
		# build the new parent (block1) and child (block2) blocks
		block1 = self._split_new(addresses[:index])
		block2 = self._split_new(addresses[index:])

		# update this block to with the new parent information
		self.bytes = block1.bytes
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

	def to_digraph(self):
		t_instructions = tuple(self.instructions.values())
		graph = networkx.DiGraph()
		graph.add_nodes_from(t_instructions)

		_register_in_set = lambda reg1, reg_set: any(reg1 & reg2 for reg2 in reg_set)

		constraints = collections.defaultdict(collections.deque)
		for idx, ins in enumerate(t_instructions):
			for reg in ins.registers.accessed:
				# for each accessed register, we search backwards to find when it was set
				for pos in reversed(range(0, idx)):
					o_ins = t_instructions[pos]
					if _register_in_set(reg, o_ins.registers.modified):
						constraints[ins].append(o_ins)
						break

			for reg in ins.registers.stored:
				# for each stored register, we search both forwards and backwards to ensure it's
				# stored between the correct modifications
				for pos in reversed(range(0, idx)):
					o_ins = t_instructions[pos]
					if _register_in_set(reg, o_ins.registers.modified):
						constraints[ins].append(o_ins)

				for pos in range(idx + 1, len(t_instructions)):
					o_ins = t_instructions[pos]
					if _register_in_set(reg, o_ins.registers.modified):
						constraints[o_ins].append(ins)
						break

		for child, dependencies in constraints.items():
			for parent in dependencies:
				graph.add_edge(parent, child)

		ins_ptr = ir.IRRegister.from_arch(self.arch, 'ip')
		leaf_nodes = set(self.instructions.values()) - set(itertools.chain(*constraints.values()))
		exit_node = next((ins for ins in leaf_nodes if ins_ptr in ins.registers.modified), None)
		if exit_node is not None:
			leaf_nodes.remove(exit_node)
			for leaf_node in leaf_nodes:
				graph.add_edge(leaf_node, exit_node)
		return graph

	def to_graphviz(self):
		n_graph = self.to_digraph()
		g_graph = graphviz.Digraph()
		for node in n_graph.nodes:
			g_graph.node("0x{0:04x}".format(node.address), "0x{0:04x} {1}".format(node.address, node.source))
		for parent, child in n_graph.edges:
			g_graph.edge(
				"0x{0:04x}".format(parent.address),
				"0x{0:04x}".format(child.address),
				constraint='true'
			)
		return g_graph

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

	def shuffle(self):
		instructions = self._shuffle_instructions()
		blob = b''.join(bytes(ins) for ins in instructions)
		return self.__class__.from_bytes(blob, self.arch, self.address)

	def _shuffle_instructions(self):
		constraints = self.to_digraph()
		shuffled = collections.deque()
		# the initial choices are any node without a predecessor (dependency)
		choices = set(node for node in constraints.nodes if len(tuple(constraints.predecessors(node))) == 0)
		while choices:  # continue to make selections while we have choices
			selection = random.choice(tuple(choices))  # make a selection
			choices.remove(selection)
			shuffled.append(selection)
			# analyze the nodes which are successors (dependants) of the selection
			for successor in constraints.successors(selection):
				# skip the node if it's already been added
				if successor in shuffled:
					continue
				# or if all of it's predecessors (dependencies) have not been met
				if not all(predecessor in shuffled for predecessor in constraints.predecessors(successor)):
					continue
				choices.add(successor)
		return shuffled

	def pp_asm(self):
		for ins in self.instructions.values():
			print("0x{ins.address:04x}  {ins.bytes_hex: <10}  {ins.source}".format(ins=ins))
