#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  crimson_forge/servicizer.py
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

import functools
import os

relpath = functools.partial(os.path.join, os.path.dirname(os.path.realpath(__file__)), '..')

import crimson_forge.assembler as assembler
import crimson_forge.utilities as utilities

architectures = utilities.architectures

PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

def to_windows_service(arch, payload, service_name='Crimson Forge', writable=False):
	source_path = relpath('data', 'stubs', arch.name.lower(), 'service_wrapper.jnj.asm')
	with open(source_path, 'r') as file_h:
		text = file_h.read()
	text = assembler.render_source(arch, text, variables={
		'payload': payload,
		'permissions': (PAGE_EXECUTE_READWRITE if writable else PAGE_EXECUTE_READ),
		'service_name': service_name
	})
	return assembler.assemble_source(arch, text)
