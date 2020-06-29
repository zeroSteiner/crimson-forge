#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  crimson_forge/assembler.py
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
import re
import sys

relpath = functools.partial(os.path.join, os.path.dirname(os.path.realpath(__file__)), '..')
sys.path.append(relpath())

import crimson_forge.source as source
import crimson_forge.utilities as utilities

import archinfo
import jinja_vanish
import jinja2

architectures = utilities.architectures

@jinja_vanish.markup_escape_func
def _asm_escape(value):
	if isinstance(value, int):
		return "0x{:x}".format(value)
	return value

def _block_api_hash(*args):
	return "0x{:>08x}".format(source.block_api_hash(*args))

def _jinja_assert(value, message):
	if not value:
		raise AssertionError("Jinja assertion '{0}' failed".format(message))
	return ''

def _jinja_bw_or(*values):
	result = 0
	for value in values:
		result |= value
	return result

def assemble_source(arch, text, base=0x1000):
	if isinstance(text, source.SourceCode):
		text = str(text)
	text = source.remove_comments(text)

	if isinstance(arch, (archinfo.ArchAMD64, archinfo.ArchX86)):
		# apply this syntax fixup to add 'ptr' to reference operations
		# example: `mov eax, dword [rdx+60]` -> `mov eax, dword ptr [rdx+60]`
		text = re.sub(r'(\s[dq]?word|byte) \[', r'\1 ptr [', text, flags=re.IGNORECASE)
		# apply this syntax fixup to move segment selectors outside of brackets
		# example: `mov rdx, [gs:rdx+96]` -> `mov rdx, gs:[rdx+96]`
		text = re.sub(r'([\w,]\s*)\[([gs]s):(\s*\w)', r'\1\2:[\3', text, flags=re.IGNORECASE)

	return bytes(arch.keystone.asm(text, base)[0])

def render_source(arch, text, variables=None):
	environment = jinja_vanish.DynAutoEscapeEnvironment(
		autoescape=True,
		escape_func=_asm_escape,
		extensions=['jinja2.ext.do'],
		loader=jinja2.FileSystemLoader([os.getcwd(), relpath('data', 'stubs')]),
		lstrip_blocks=True,
		trim_blocks=True,
	)
	# functions
	environment.globals['api_hash'] = _block_api_hash
	environment.globals['arch'] = arch.name.lower()
	environment.globals['assert'] = _jinja_assert
	environment.globals['bw_or'] = _jinja_bw_or
	environment.globals['raw_bytes'] = source.raw_bytes
	environment.globals['raw_string'] = source.raw_string
	template = environment.from_string(text)
	variables = variables or {}
	return template.render(**variables)
