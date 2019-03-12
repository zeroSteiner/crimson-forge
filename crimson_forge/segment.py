#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  crimson_forge/segment.py
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
import io
import logging

import crimson_forge.base as base
import crimson_forge.block as block
import crimson_forge.ir as ir
import crimson_forge.source as source
import crimson_forge.ssa as ssa
import crimson_forge.tailor as tailor

import angr
import capstone
import graphviz
import keystone

logger = logging.getLogger('crimson-forge.segment')

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
	def for_address(self, address):
		for blk in self.values():
			if blk.address <= address <= (blk.address + blk.size - 1):
				return blk
		return None

	def get_next(self, blk):
		if not isinstance(blk, block.BlockBase):
			raise TypeError('argument 1 must be a BlockBase instance')
		return self.get(blk.address + blk.size)

	def to_graphviz(self):
		graph = graphviz.Digraph()
		for blk in self.values():
			if isinstance(blk, block.DataBlock):
				continue
			label = "<<table border=\"0\" cellborder=\"0\" cellspacing=\"1\">"
			for line in blk.instructions.pp_asm(stream=None).split('\n'):
				label += "<tr><td align=\"left\">'{0}'</td></tr>".format(line)
			label += "</table>>"
			graph.node(str(blk.address), label=label, fontname='courier new', shape='rectangle')
		for blk in self.values():
			if isinstance(blk, block.DataBlock):
				continue
			for child_address in blk.children:
				if child_address in self:
					graph.edge(str(blk.address), str(child_address), constraint='true')
				else:
					graph.node(str(child_address), "0x:{:04x}".format(child_address), shape='plain')
		return graph

class ExecutableSegment(base.Base):
	def __init__(self, blob, arch, base=0x1000):
		super(ExecutableSegment, self).__init__(blob, arch, base)
		self.entry_address = self.address
		self._md = capstone.Cs(self.arch.cs_arch, self.arch.cs_mode)
		self._md.detail = True
		# the mnemonic filter in some of the instruction post-processors requires intel syntax and not at&t so
		# explicitly set it here and do not change it
		self._md.syntax = capstone.CS_OPT_SYNTAX_INTEL

		self.cs_instructions.update((ins.address, ins) for ins in self._disassemble(blob))
		self.blocks = _Blocks()
		for ins_addr in tuple(self.cs_instructions.keys()):
			if self.blocks.for_address(ins_addr) is not None:
				continue
			self._process_irsb(self.__vex_lift(blob[ins_addr-base:], base=ins_addr))

		# order the blocks by their address
		self.blocks = _Blocks((addr, self.blocks[addr]) for addr in sorted(self.blocks.keys()))
		for block in self.blocks.values():
			self.vex_instructions.update(block.vex_instructions.items())

		# prune capstone instructions without corresponding vex instructions
		for ins_addr in tuple(self.cs_instructions.keys()):
			if ins_addr not in self.vex_instructions:
				del self.cs_instructions[ins_addr]
		self.instructions = _InstructionsProxy(arch, self.cs_instructions, self.blocks)

	def __process_irsb_jump(self, jump):
		# get the parent basic-block which should already exist
		bblock = self.blocks.for_address(jump.from_address)
		if bblock is None:
			raise RuntimeError('parent basic-block is None')
		# check if the jump target belongs to an existing block
		jmp_bblock = self.blocks.for_address(jump.to_address)
		if isinstance(jmp_bblock, block.BasicBlock):
			if jump.to_address in jmp_bblock.instructions:
				connect_to_self = jmp_bblock is bblock
				if jump.to_address != jmp_bblock.address:
					jmp_bblock = jmp_bblock.split(jump.to_address)
					self.blocks[jmp_bblock.address] = jmp_bblock
				if connect_to_self:
					jmp_bblock.connect_to(jmp_bblock)
				bblock.connect_to(jmp_bblock)
			else:
				logger.warning("Block 0x%04x jumps to the middle of an instruction at 0x%04x", bblock.address, jump.to_address)
		elif isinstance(jmp_bblock, block.DataBlock):
			logger.warning("Block 0x%04x jumps to a data-block at 0x%04x", bblock.address, jump.to_address)
		else:
			# if no block is found, build a new one from the blob (if there is data left)
			blob = self.bytes[jump.to_address - self.base:]
			if blob:
				self._process_irsb(self.__vex_lift(blob, jump.to_address), parent=self.blocks.for_address(jump.from_address))

	def __process_irsb_jk_no_decode(self, irsb):
		offset = irsb.addr - self.base
		size = irsb.size
		while self.blocks.for_address(self.base + offset + size) is None and offset + size < self.size:
			size += 1
		blob = self.bytes[offset:offset + size]
		blk = self.blocks.for_address(irsb.addr)
		if blk is None:
			logger.info("Creating data-block from IRSB ending with %s at 0x%04x", irsb.jumpkind, irsb.addr)
			blk = block.DataBlock(blob, self.arch, irsb.addr)
			self.blocks[blk.address] = blk
		else:
			if isinstance(blk, block.BasicBlock):
				ins = blk.instructions.for_address(irsb.addr)
				if blk.address != ins.address:
					blk = blk.split(ins.address)
				blk = blk.to_data_block()
				self.blocks[blk.address] = blk
			blk.bytes += blob
		return blk

	def __vex_lift(self, blob, base=None):
		base = self.base if base is None else base
		return ir.lift(blob, base, self.arch)

	def _disassemble(self, blob, base=None):
		base = self.base if base is None else base
		yield from self._md.disasm(blob, base)

	def _permutation_bytes(self):
		blob = b''
		# if not replacing instructions, use the original instruction bytes
		for blk in self.blocks.values():
			if isinstance(blk, block.DataBlock):
				blob += blk.bytes
			elif isinstance(blk, block.BasicBlock):
				for instruction in blk.permutation_instructions(replacements=False):
					blob += instruction.bytes
		return blob

	def _permutation_bytes_replacements(self):
		# if replacing instructions, operate at the source level to use labels
		src_code = self.permutation_source(replacements=True)
		exec_seg_src = str(src_code)
		exec_seg_src = source.remove_comments(exec_seg_src)
		try:
			blob = bytes(self.arch.keystone.asm(exec_seg_src, self.address)[0])
		except keystone.KsError as error:
			logger.error('Failed to assemble source, error: ' + error.message)
			return None
		return blob

	def _process_irsb(self, irsb, parent=None):
		if irsb.jumpkind == ir.JumpKind.NoDecode:
			return self.__process_irsb_jk_no_decode(irsb)

		offset = irsb.addr - self.base
		blob = self.bytes[offset:offset + irsb.size]
		cs_instructions = collections.OrderedDict()
		for addr in irsb.instruction_addresses:
			if addr not in self.cs_instructions:
				cs_ins = next(self._disassemble(self.bytes[addr - self.base:], addr), None)
				if cs_ins is None:
					logger.error("Failed to disassemble non-existent instruction referenced by the IRSB at 0x{:04x}".format(addr))
					raise RuntimeError('failed to disassemble referenced instruction')
				logger.debug("Disassembled non-existent instruction referenced by the IRSB at 0x{:04x}".format(addr))
				self.cs_instructions[addr] = cs_ins
			cs_instructions[addr] = self.cs_instructions[addr]

		bblock = block.BasicBlock.from_irsb(blob, cs_instructions, irsb)
		if parent is not None:
			parent.connect_to(bblock)
		self.blocks[bblock.address] = bblock
		# search blocks to see if any instructions overlap with an existing block and if so
		# split and propagate relationships
		for address in tuple(bblock.cs_instructions.keys())[1:]:
			existing_bblock = self.blocks.get(address, None)
			if existing_bblock:
				bblock.split(existing_bblock.address)
				bblock.connect_to(existing_bblock)
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
				jump = ir.IRJump(self.arch, bblock.address + bblock.size, tuple(bblock.cs_instructions.keys())[-1])
				self.__process_irsb_jump(jump)
		return bblock

	@property
	def base(self):
		return self.address

	@classmethod
	def from_source(cls, text, arch, base=0x1000):
		blob, _ = arch.keystone.asm(source.remove_comments(text), base)
		return cls(bytes(blob), arch, base=base)

	@classmethod
	def from_source_file(cls, source_file, *args, **kwargs):
		with open(source_file, 'r') as file_h:
			source = file_h.read()
		return cls.from_source(source *args, **kwargs)

	def permutation(self):
		blob = self.permutation_bytes()
		return self.__class__(blob, self.arch, self.base)

	def permutation_bytes(self, replacements=True):
		if replacements:
			blob = self._permutation_bytes_replacements()
		else:
			blob = self._permutation_bytes()
		return blob

	def permutation_count(self):
		count = 1
		for blk in self.blocks.values():
			if not isinstance(blk, block.BasicBlock):
				continue
			count *= blk.permutation_count()
		return count

	def permutation_source(self, replacements=True):
		src_code = source.SourceCode(self.arch)
		for blk in self.blocks.values():
			if isinstance(blk, block.DataBlock):
				src_code.extend(blk.source_iter(), blk)
			elif isinstance(blk, block.BasicBlock):
				graph = blk.to_digraph()
				if replacements:
					graph = tailor.alter(graph)
				src_code.extend(graph.to_instructions(), blk)
			else:
				raise TypeError('block type is not supported')
		return src_code

	@property
	def ssa_variables(self):
		return ssa.Variables(self.instructions)

	def to_angr(self):
		project = angr.Project(io.BytesIO(self.bytes), main_opts={
			'arch': self.arch,
			'backend': 'blob',
			'base_addr': self.base,
			'entry_point': self.base,
			'filename': 'crimson-forge.bin'
		})
		return project

	def to_source(self):
		src_code = source.SourceCode(self.arch)
		src_code.extend([
			source.SourceLineComment("arch: {}".format(self.arch.name.lower())),
			source.SourceLineComment("base address: 0x{:04x}".format(self.address)),
			source.SourceLineLabel('_start')
		])
		for blk in self.blocks.values():
			if isinstance(blk, block.DataBlock):
				src_code.extend(blk.source_iter(), blk)
			elif isinstance(blk, block.BasicBlock):
				src_code.extend(blk.instructions.values(), blk)
			else:
				raise TypeError('block type is not supported')
		return src_code
