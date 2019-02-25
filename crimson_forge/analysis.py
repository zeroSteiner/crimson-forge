#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  crimson_forge/analysis.py
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
import contextlib
import functools
import logging

import crimson_forge.block as block
import crimson_forge.ir as ir

import angr
import boltons.iterutils

logger = logging.getLogger('crimson-forge.analysis')

class SelfReferenceTracker(angr.SimStatePlugin):
	name = 'self_references'
	stack_drift = 16  # +/- 16 entries from the stack pointer (natively-sized)
	# the reference is made of three addresses
	#    * instruction: the address of the instruction which made the reference
	#    * stack: the address on the stack where the reference was placed
	#    * referenced: the address that is referenced
	Reference = collections.namedtuple('Reference', ('instruction', 'stack', 'referenced'))
	ReferenceExpression = collections.namedtuple('ExpressionReference', ('expression', 'reference', 'tainted'))
	def __init__(self, blocks, copied=False):
		super(SelfReferenceTracker, self).__init__()
		self.blocks = blocks
		self.copied = copied
		self.breakpoints = {}
		# these are references that exist on the stack
		self.references = {}
		self.expressions = {}

	@classmethod
	def _breakpoint(cls, state, event_type):
		instance = getattr(state, cls.name)
		handler = getattr(instance, '_breakpoint_' + event_type, None)
		if handler is None:
			logger.info("Hit breakpoint for event: %s with no handler", event_type)
			return
		with instance.disabled():
			handler(state)

	def _breakpoint_expr(self, state):
		expr = state.inspect.expr
		if not expr.symbolic:
			return
		if expr in self.expressions:
			return
		if any(symbol.variables & expr.variables for symbol in self.expressions.keys()):
			self.expressions[expr] = self.ReferenceExpression(expr, None, True)
			logger.info('New tainted expression identified')

	def _breakpoint_mem_read(self, state):
		if not state.regs.ip.concrete:
			return  # can't deal with non-concrete values
		if not state.regs.sp.concrete:
			return  # can't deal with non-concrete values
		ip_addr = state.solver.eval(state.regs.ip)
		stack_addr = state.solver.eval(state.regs.sp)
		if state.inspect.mem_read_address.concrete:
			read_addr = state.solver.eval(state.inspect.mem_read_address)
			logger.debug("[0x%04x] mem-read: (expr) %r @0x%04x", ip_addr, state.inspect.mem_read_expr, read_addr)
		if not self.__addr_is_on_stack(state, stack_addr, state.inspect.mem_read_address):
			return
		reference = self.references.get(read_addr)
		if reference is None:
			return
		logger.info("[0x%04x] Tainted reference accessed", ip_addr)
		mem_read_expr = state.solver.BVS("self-reference @0x{:x}".format(reference.stack), state.inspect.mem_read_expr.length)
		state.add_constraints(mem_read_expr == state.inspect.mem_read_expr)
		state.inspect.mem_read_expr = mem_read_expr
		self.expressions[mem_read_expr] = self.ReferenceExpression(mem_read_expr, reference, False)

	def __addr_is_on_stack(self, state, stack_addr, address):
		if not address.concrete:
			return False  # can't deal with non-concrete values
		address = state.solver.eval(address)
		if address % state.arch.bytes:
			return False  # address isn't aligned with bytes
		offset = address // state.arch.bytes
		stack_offset = stack_addr // state.arch.bytes
		if abs(stack_offset - offset) > self.stack_drift:
			return False
		return True

	def __breakpoint_mem_write(self, state, stack_addr, ip_addr):
		if not self.__addr_is_on_stack(state, stack_addr, state.inspect.mem_write_address):
			return
		write_expr = state.inspect.mem_write_expr
		if not write_expr.concrete:
			return
		# at this point we know the write is taking place at a properly aligned location on the stack within
		# +/- the stack_drift value
		ins_block = self.blocks.for_address(ip_addr)
		if ins_block is None:
			return
		write_value = state.solver.eval(write_expr)
		if ins_block.next_address == write_value:
			return True
		write_value_block = self.blocks.for_address(write_value)
		if write_value_block is None:
			return
		if write_value_block is ins_block or ins_block.address in write_value_block.children:
			return True
		return

	def _breakpoint_mem_write(self, state):
		if not state.regs.ip.concrete:
			return  # can't deal with non-concrete values
		if not state.regs.sp.concrete:
			return  # can't deal with non-concrete values
		ip_addr = state.solver.eval(state.regs.ip)
		if state.inspect.mem_write_address.concrete:
			logger.debug("[0x{:04x}] mem-write: (expr) {!r} @0x{:04x}".format(ip_addr, state.inspect.mem_write_expr, state.solver.eval(state.inspect.mem_write_address)))
		stack_addr = state.solver.eval(state.regs.sp)
		if self.__breakpoint_mem_write(state, stack_addr, ip_addr):
			self.references[stack_addr] = self.Reference(ip_addr, stack_addr, state.solver.eval(state.inspect.mem_write_expr))
			logger.info("[0x%04x] Marking stack address 0x%04x as IP tainted", ip_addr, stack_addr)
		elif stack_addr in self.references:
			logger.info("[0x%04x] Unmarking stack address 0x%04x as IP tainted", ip_addr, stack_addr)
			del self.references[stack_addr]

	def _make_breakpoint(self, event_type, when=angr.BP_AFTER):
		bp = self.state.inspect.make_breakpoint(event_type, when=when, action=functools.partial(self._breakpoint, event_type=event_type))
		self.breakpoints[event_type] = bp

	@angr.SimStatePlugin.memo
	def copy(self, memo):
		new = self.__class__(self.blocks, copied=True)
		new.breakpoints = self.breakpoints
		new.references = self.references.copy()
		new.expressions = self.expressions.copy()
		return new

	@contextlib.contextmanager
	def disabled(self):
		for event_type, bp in self.breakpoints.items():
			self.state.inspect.remove_breakpoint(event_type, bp=bp)
		yield
		for event_type, bp in self.breakpoints.items():
			self.state.inspect.add_breakpoint(event_type, bp=bp)

	def register(self, state):
		state.register_plugin(self.name, self)

	def init_state(self, *args, **kwargs):
		super(SelfReferenceTracker, self).init_state(*args, **kwargs)
		if not self.breakpoints:
			# https://github.com/angr/angr-doc/blob/master/docs/simulation.md#breakpoints
			self._make_breakpoint('expr')
			self._make_breakpoint('mem_read')
			self._make_breakpoint('mem_write')

def check_block_sizes(exec_seg):
	# use this function when there is a size mismatch to help identify where it is, the faulty blocks are logged
	for block, next_block in boltons.iterutils.pairwise(exec_seg.blocks.values()):
		prefix = "{} 0x{:04x} (size: {:,} bytes) ".format(block.__class__.__name__, block.address, block.size)
		if next_block.address < block.address + block.size:
			message = "over runs with next block 0x{:04x} ".format(next_block.address)
		elif next_block.address > block.address + block.size:
			message = "under runs with next block 0x{:04x} ".format(next_block.address)
		else:
			continue
		logger.error(prefix + message + "(delta: {:+,} bytes)".format(block.address + block.size - next_block.address))

def symexec_data_identification_cfg(exec_seg):
	# This analysis uses angr to create a control flow graph and then checks for path terminator nodes to identify
	# static data embedded within an executable segment. This should only be necessary within the context of shellcode.
	project = exec_seg.to_angr()
	logger.info('Recovering the control flow graph')
	cfg = project.analyses.CFGEmulated()  # this can take a few seconds
	for node in cfg.deadends:
		if node.name != 'PathTerminator':
			continue
		blk = exec_seg.blocks.for_address(node.addr)
		if blk is None:
			logger.warning('The control flow graph identified a path terminator for a non-existent block')
		elif blk.address == node.addr:
			if isinstance(blk, block.BasicBlock):
				logger.info("Converting basic-block at 0x%04x to a data-block", blk.address)
				exec_seg.blocks[node.addr] = blk.to_data_block()
			elif isinstance(blk, block.DataBlock):
				logger.info("Block 0x%04x was already identified as a data-block", blk.address)
		elif isinstance(blk, block.BasicBlock):
			dblock = blk.split(node.addr).to_data_block()
			exec_seg.blocks[node.addr] = dblock

def symexec_data_identification_ret(exec_seg):
	"""
	This analysis identifies basic-blocks with a single parent ending in a call
	jump and tries to confirm that they do in fact return.
	"""
	project = exec_seg.to_angr()
	for blk in tuple(exec_seg.blocks.values()):
		if blk.address not in exec_seg.blocks:
			continue  # a previous iteration of this loop caused this block to be absorbed
		if not isinstance(blk, block.BasicBlock):
			continue
		if len(blk.parents) != 1:
			continue
		parent_bblock = tuple(blk.parents.values())[0]
		if parent_bblock.ir_jumpkind != ir.JumpKind.Call:
			continue
		if blk.address != parent_bblock.address + parent_bblock.size:
			continue
		if len(parent_bblock.children) == 1:
			# this would be the case if the call is not a constant, e.g. "call eax"
			continue
		children = parent_bblock.children.copy()
		children.pop(blk.address)
		callee_bblock = tuple(children.values())[0]

		state = project.factory.call_state(callee_bblock.address, ret_addr=blk.address)
		simgr = project.factory.simulation_manager(state)
		logger.debug("Verifying execution path reaches basic-block at 0x%04x", blk.address)
		simgr.explore(find=blk.address, num_find=1)

		if simgr.found:
			continue
		logger.info("Converting basic-block at 0x%04x to a data-block", blk.address)
		blk = blk.to_data_block()
		exec_seg.blocks[blk.address] = blk
		next_blk = exec_seg.blocks.get_next(blk)
		while next_blk:
			# creat a cascading affect of basic to data block conversions
			if isinstance(next_blk, block.BasicBlock) and not next_blk.parents:
				logger.debug("Converting basic-block at 0x%04x to a data-block (via cascading)", next_blk.address)
				next_blk = next_blk.to_data_block()
			if isinstance(next_blk, block.DataBlock):
				logger.debug("Absorbing data-block at 0x%04x into data-block at 0x%04x (via cascading)", next_blk.address, blk.address)
				blk.bytes += next_blk.bytes
				if next_blk.address in exec_seg.blocks:
					del exec_seg.blocks[next_blk.address]
			else:
				break
			next_blk = exec_seg.blocks.get_next(next_blk)

def symexec_tainted_self_reference_identification(exec_seg):
	project = exec_seg.to_angr()
	state = project.factory.blank_state()
	state.regs.ip = exec_seg.entry_address
	# todo: populate the tracker with an initial entry when it makes sense to start from a call-state
	SelfReferenceTracker(exec_seg.blocks).register(state)

	def _simulate_state_recursively(state, history):
		target_address = state.solver.eval(state.regs.ip)
		blk = exec_seg.blocks.get(target_address)
		if blk is None:
			# todo: this should probably do something more intelligent, we're losing track here if this occurs
			raise RuntimeError('Encountered address that does not correlate to a block')
		simgr = project.factory.simulation_manager(state)
		simgr.step(num_inst=len(blk.instructions))
		result = True
		for new_state in simgr.active:
			if any(ref_expr.tainted for ref_expr in new_state.self_references.expressions.values()):
				return False
			if not new_state.regs.ip.concrete:
				continue
			history_entry = (target_address, new_state.solver.eval(new_state.regs.ip))
			if history_entry in history:
				continue
			history.append(history_entry)
			result = result and _simulate_state_recursively(new_state, history)
			history.pop()
		return result
	return not _simulate_state_recursively(state, collections.deque())
