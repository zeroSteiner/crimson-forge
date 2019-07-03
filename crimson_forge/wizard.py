#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  crimson_forge/wizard.py
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

import os

import crimson_forge
import crimson_forge.cli as cli
import crimson_forge.utilities as utilities

import bullet
import bullet.client
import bullet.colors
import bullet.utils
import termcolor

def _access_file(path, mode):
	return os.path.isfile(path) and os.access(path, mode)

bullet_formatting = {
	'align': 2,
	'margin': 1
}

def _prompt(prompt):
	return termcolor.colored('[?] ', 'cyan', attrs=['bold']) + prompt + ' '

def _bullet(prompt, choices, default=None):
	choices = tuple(choices)
	if default is not None and default in choices:
		default = choices.index(default)
	else:
		default = None
	choices = tuple("{!s: <20}".format(choice) for choice in choices)
	selected = bullet.Bullet(
		_prompt(prompt),
		choices=choices,
		# style
		background_color='',
		background_on_switch=bullet.colors.background['red'],
		bullet_color=bullet.colors.foreground['white'],
		word_on_switch=bullet.colors.foreground['white'],
		**bullet_formatting
	).launch(default=default)
	return selected.rstrip()

def _bullet_check(prompt, choices, default=None):
	choices = tuple(choices)
	if default is not None:
		default = [choices.index(value) for value in default if value in choices]
	choices = tuple("{!s: <20}".format(choice) for choice in choices)
	selected = bullet.Check(
		_prompt(prompt),
		choices=choices,
		# style
		background_color='',
		background_on_switch=bullet.colors.background['red'],
		check_color=bullet.colors.foreground['red'],
		check_on_switch=bullet.colors.foreground['white'],
		word_on_switch=bullet.colors.foreground['white'],
		**bullet_formatting
	).launch(default=default)
	selected = tuple(member.rstrip() for member in selected)
	return selected

def _bullet_input(prompt):
	return bullet.Input(_prompt(prompt)).launch()

def _bullet_input_writable_file_path(prompt):
	file_path = None
	while file_path is None:
		file_path = _bullet_input(prompt)
		if file_path is None:
			break
		if os.path.isdir(file_path):
			utilities.print_error('Please specify a file path and not a directory')
			file_path = None
		elif os.path.isfile(file_path):
			if not os.access(file_path, os.W_OK):
				utilities.print_error('Can not write to the specified file path')
				file_path = None
		else:
			dir_path = os.path.dirname(file_path)
			if not os.access(dir_path, os.W_OK):
				utilities.print_error('Can not create the specified file')
				file_path = None
	return file_path

def _bullet_yes_no(prompt, default='yes'):
	if default == 'yes':
		prompt += ' [Y/n]'
	elif default == 'no':
		prompt += ' [y/N]'
	else:
		raise ValueError('default must be either \'yes\' or \'no\'')
	return bullet.YesNo(_prompt(prompt + ':'), prompt_prefix='').launch(default=default[0])

def _get_analysis_profile():
	choices = ['automatic']
	choices.extend([profile.value for profile in cli.AnalysisProfile])
	analysis_profile = _bullet(
		'Please select an analysis profile:',
		choices,
		default='automatic'
	)
	if analysis_profile == 'automatic':
		analysis_profile = None
	return analysis_profile

def _get_input_format(input_file):
	input_format = _bullet(
		'Please select the input file format:',
		[cli.DataFormat.RAW.value, cli.DataFormat.SOURCE.value],
		cli.DataFormat.guess(input_file).value
	)
	return input_format

def _get_output_formats():
	choices = [data_format.value for data_format in cli.DataFormat]
	output_formats = _bullet_check(
		'Please select the output formats to generate:',
		choices,
		default=choices
	)
	return output_formats

def main():
	print(cli.BANNER)
	printer = crimson_forge.utilities
	arguments = []

	arch = _bullet('Please select the target architecture:', cli.architectures.keys(), default='x86')
	arguments.extend(('--arch', arch))

	input_file = None
	while input_file is None:
		input_file = _bullet_input('Please select the input file path:')
		if input_file is None:
			return os.EX_USAGE
		if not _access_file(input_file, mode=os.R_OK):
			printer.print_error('The selected file is invalid')
			input_file = None

	input_format = _get_input_format(input_file)
	arguments.extend(('--format', input_format))

	analysis_profile = _get_analysis_profile()
	if analysis_profile:
		arguments.extend(('--analysis-profile', analysis_profile))

	output_file = None
	if _bullet('Please select the operation mode:', ('analyze only', 'generate output'), default='generate output') == 'generate output':
		while output_file is None:
			output_file = _bullet_input_writable_file_path('Please select the output file path:')
			if output_file is None:
				return os.EX_USAGE
		for data_format in _get_output_formats():
			arguments.extend(('--output-format', data_format))

	# add on the positional arguments last
	arguments.append(input_file)
	if output_file:
		arguments.append(output_file)
	printer.print_status('Final arguments: ' + ' '.join(arguments))

	if _bullet_yes_no('Would you like to save the arguments to a file?'):
		arguments_file = _bullet_input_writable_file_path('Please select the arguments file path:')
		if arguments_file is None:
			return os.EX_USAGE
		with open(arguments_file, 'w') as file_h:
			file_h.write('\n'.join(arguments))

	arguments.insert(0, '--skip-banner')
	return cli.main(arguments)

if __name__ == '__main__':
	main()