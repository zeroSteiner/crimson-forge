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

import logging

import crimson_forge.block as block
import crimson_forge.ir as ir

import boltons.iterutils

logger = logging.getLogger('crimson-forge.analysis')

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
	# This analysis identifies basic-blocks with a single parent ending in a call jump and tries to confirm that they
	# do in fact return.
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
		next_blk = exec_seg.blocks.get(blk.address + blk.size)
		if isinstance(next_blk, block.DataBlock):
			blk.bytes += next_blk.bytes
			del exec_seg.blocks[next_blk.address]
