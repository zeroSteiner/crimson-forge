#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  crimson_forge/binary.py
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

import crimson_forge.base as base
import crimson_forge.block as block
import crimson_forge.ir as ir
import crimson_forge.utilities as utilities

import graphviz

def _irsb_jumps(irsb):
	jumps = collections.deque()
	for _, _, stmt in irsb.exit_statements:
		jumps.append(ir.IRJump(irsb.arch, stmt.dst.value, ir.irsb_address_for_statement(irsb, stmt), stmt.jumpkind))
	if irsb.default_exit_target is not None:
		# the from_address will be the last instruction
		from_address = ir.irsb_address_for_statement(irsb, irsb.statements[-1])
		jumps.append(ir.IRJump(irsb.arch, irsb.default_exit_target, from_address, irsb.jumpkind))
	# return a sorted-tuple to make the result deterministic which makes debugging and reproducing results easier
	return tuple(sorted(jumps, key=lambda jump: (jump.from_address, jump.to_address)))

class _InstructionsProxy(base.InstructionsProxy):
	def __init__(self, arch, cs_instructions, blocks):
		super(_InstructionsProxy, self).__init__(arch, cs_instructions)
		self._blocks = blocks

	def _resolve_ir(self, address):
		for block in self._blocks.values():
			if address in block.vex_instructions:
				return block.vex_instructions[address], block.ir_tyenv
			if block.address > address:
				break
		raise KeyError('instruction address not found')

class _Blocks(collections.OrderedDict):
	def to_graphviz(self):
		graph = graphviz.Digraph()
		for block in self.values():
			label = "<<table border=\"0\" cellborder=\"0\" cellspacing=\"1\">"
			for line in block.instructions.pp_asm(stream=None).split('\n'):
				label += "<tr><td align=\"left\">{0}</td></tr>".format(line)
			label += "</table>>"
			graph.node(str(block.address), label=label, fontname='courier new', shape='rectangle')
		for block in self.values():
			for child_address in block.children:
				if child_address in self:
					graph.edge(str(block.address), str(child_address), constraint='true')
				else:
					graph.node(str(child_address), "0x:{:04x}".format(child_address), shape='plain')
		return graph

	def for_address(self, address):
		return next((block for block in self.values() if address in block.instructions), None)

# todo: rename this to ExecutableSegment for accuracy
class Binary(base.Base):
	def __init__(self, blob, arch, base=0x1000):
		super(Binary, self).__init__(blob, arch, base)
		self.cs_instructions.update((ins.address, ins) for ins in self._disassemble(blob))
		self.blocks = _Blocks()
		for ins_addr in self.cs_instructions:
			if any(ins_addr in block.instructions for block in self.blocks.values()):
				continue
			self._process_irsb(self.__vex_lift(blob[ins_addr-base:], base=ins_addr))

		# order the blocks by their address
		self.blocks = _Blocks((addr, self.blocks[addr]) for addr in sorted(self.blocks.keys()))
		for block in self.blocks.values():
			self.vex_instructions.update(block.vex_instructions.items())
		self.instructions = _InstructionsProxy(arch, self.cs_instructions, self.blocks)

	@property
	def base(self):
		return self.address

	def _disassemble(self, blob):
		yield from self.arch.capstone.disasm(blob, self.base)

	def _process_irsb(self, irsb, parent=None):
		offset = irsb.addr - self.base
		blob = self.bytes[offset:offset + irsb.size]
		cs_instructions = collections.OrderedDict()
		cs_instructions.update((addr, self.cs_instructions[addr]) for addr in irsb.instruction_addresses)
		bblock = block.BasicBlock.from_irsb(blob, cs_instructions, irsb)
		if parent is not None:
			parent.connect_to(bblock)
		self.blocks[bblock.address] = bblock
		# search blocks to see if any instructions overlap with an existing block and if so
		# split and propagate relationships
		for address in tuple(bblock.cs_instructions.keys())[1:]:
			original_bblock = self.blocks.pop(address, None)
			if original_bblock is None:
				continue
			break
		# we split the original block, so irsb is no longer an accurate representation and
		# so we skip this step since the relations are already connected
		else:
			last_address = tuple(bblock.cs_instructions.keys())[-1]
			for jump in _irsb_jumps(irsb):
				if not (jump.kind == ir.JumpKind.Boring or ir.JumpKind.returns(jump.kind)):
					continue
				if jump.from_address != last_address:
					sub_bblock = bblock.split(jump.from_address + self.cs_instructions[jump.from_address].size)
					self.blocks[sub_bblock.address] = sub_bblock
				self.__process_irsb_jump(jump)
			if ir.JumpKind.returns(irsb.jumpkind):
				jump = ir.IRJump(self.arch, bblock.address + len(bblock.bytes), tuple(bblock.cs_instructions.keys())[-1])
				self.__process_irsb_jump(jump)
		return bblock

	def __process_irsb_jump(self, jump):
		# get the parent basic-block which should already exist
		bblock = self.blocks.for_address(jump.from_address)
		if bblock is None:
			raise RuntimeError('parent basic-block is None')
		# check if the jump target belongs to an existing block
		jmp_bblock = self.blocks.for_address(jump.to_address)
		if jmp_bblock:
			connect_to_self = jmp_bblock is bblock
			if jump.to_address != jmp_bblock.address:
				jmp_bblock = jmp_bblock.split(jump.to_address)
				self.blocks[jmp_bblock.address] = jmp_bblock
			if connect_to_self:
				jmp_bblock.connect_to(jmp_bblock)
			bblock.connect_to(jmp_bblock)
		else:
			# if no block is found, build a new one from the blob (if there is data left)
			blob = self.bytes[jump.to_address - self.base:]
			if blob:
				self._process_irsb(self.__vex_lift(blob, jump.to_address), parent=self.blocks.for_address(jump.from_address))

	def __vex_lift(self, blob, base=None):
		base = self.base if base is None else base
		return ir.lift(blob, base, self.arch)

	@classmethod
	def from_source(cls, source, arch, base=0x1000):
		blob, _ = arch.keystone.asm(utilities.remove_comments(source))
		return cls(bytes(blob), arch, base=base)

	@classmethod
	def from_source_file(cls, source_file, *args, **kwargs):
		with open(source_file, 'r') as file_h:
			source = file_h.read()
		return cls.from_source(source *args, **kwargs)

	def permutation(self):
		blocks = [block.permutation() for block in self.blocks.values()]
		blob = b''.join(block.bytes for block in blocks)
		return self.__class__(blob, self.arch, self.base)

	def permutation_count(self):
		count = 1
		for block in self.blocks.values():
			count *= block.permutation_count()
		return count
