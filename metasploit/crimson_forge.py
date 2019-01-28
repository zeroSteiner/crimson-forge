#!/usr/bin/env python
import os

def main():
	path = os.path.dirname(os.path.dirname(os.readlink(__file__)))
	environ = os.environ.copy()
	environ['OWD'] = os.path.abspath(os.getcwd())
	os.chdir(path)
	os.execvpe('pipenv', ['--site-packages', 'run', 'metasploit'], environ)

if __name__ == '__main__':
	main()
