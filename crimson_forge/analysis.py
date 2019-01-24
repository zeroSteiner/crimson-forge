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

logger = logging.getLogger('crimson-forge.analysis')

def symexec_data_identification(exec_seg):
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
