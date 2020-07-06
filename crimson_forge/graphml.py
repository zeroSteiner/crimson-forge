#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  crimson_forge/graphml.py
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

import xml.etree.ElementTree as ElementTree

class _GraphMLMetaAttribute(object):
	__slots__ = ('id', 'name', 'type', 'domain', 'default')
	def __init__(self, id, name=None, type='string', domain='all', default=None):
		self.id = id
		self.name = name or id
		self.type = type
		self.domain = domain
		self.default = default

GRAPHML_ATTRIBUTES = dict((attr.id, attr) for attr in [
	_GraphMLMetaAttribute('address', type='long'),
	_GraphMLMetaAttribute('type'),
	_GraphMLMetaAttribute('instruction.source', domain='node'),
	_GraphMLMetaAttribute('instruction.hex', domain='node')
])

def dump_attribute(value):
	if isinstance(value, bool):
		value = str(value).lower()
	return str(value)

class GraphMLElement(ElementTree.Element):
	def __init__(self):
		super().__init__('graphml', attrib={
			'xmlns': 'http://graphml.graphdrawing.org/xmlns',
			'xmlns:xsi': 'http://graphml.graphdrawing.org/xmlns',
			'xsi:schemaLocation': 'http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd'
		})
		for meta_attribute in GRAPHML_ATTRIBUTES.values():
			key = ElementTree.SubElement(self, 'key', attrib={
				'id': meta_attribute.id,
				'for': meta_attribute.domain,
				'attr.name': meta_attribute.name,
				'attr.type': meta_attribute.type,
			})
			if meta_attribute.default is not None:
				default = ElementTree.SubElement(key, 'default')
				default.text = dump_attribute(meta_attribute.default)

	def __str__(self):
		return ElementTree.tostring(self, encoding='unicode', xml_declaration=True)
