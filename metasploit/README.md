# Crimson Forge Metasploit Integration
Metasploit integration with Crimson Forge is currently supported by an external
evasion module. This module facilitates taking a Metasploit payload, processing
it and then converting it to a Windows Portable Executable (as with
`--output-format pe:exe`).

## Installation
To install the module, create a symbolic link to the module in the modules
folder.

1. Ensure Crimson Forge is properly installed
1. Ensure Metasploit is up to date
    * Changes from commit [0e838da5][1] (PR [#11333][2], landed 2019-02-06) must
      be present
1. Create the private modules folder if necessary
    * `mkdir -p ~/.msf4/modules/evasion/windows`
1. Create the symbolic link to the module
    * `ln -s $(pwd)/crimson_forge.py ~/.msf4/modules/evasion/windows`
1. Restart Metasploit if it is already running

[1]: https://github.com/rapid7/metasploit-framework/commit/0e838da56b2f4bb6e7d8c5ea09a46cb65dfb360a
[2]: https://github.com/rapid7/metasploit-framework/pull/11333
