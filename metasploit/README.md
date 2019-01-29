# Crimson Forge Metasploit Integration
Metasploit integration with Crimson Forge is currently supported by an external
evasion module. This module facilitates taking a Metasploit payload, processing
it and then converting it to a Windows Portable Executable (as with
`--output-format pe:exe`).

## Installation
To install the module, create a symbolic link to the module in the modules
folder.

1. Ensure Crimson Forge is properly installed.
1. Create the private modules folder if necessary.
    * `mkdir -p ~/.msf4/modules/evasion/windows`
1. Create the symbolic link to the module.
    * `ln -s $(pwd)/crimson_forge.py ~/.msf4/modules/evasion/windows`
1. Restart Metasploit if it is already running.
