# Crimson Forge Installation

## Supported Operating Systems

* Fedora 32

## Installation Instructions

1. Install prerequisites
    * Python v3.8+
    * Additional OS packages
        * `cmake`
        * `git`
        * `pipenv`
        * `z3-libs`
1. Clone the repository
    * `git clone git@github.com:zeroSteiner/crimson-forge.git`
1. Change directories into the repository
    * `cd crimson-forge`
1. Install packages with pipenv
    * `pipenv install`
1. Run `crimson-forge`
    * `pipenv run crimson-forge --help`
1. **(Optional)** Install the Metasploit Framework evasion module
    * See the [metasploit/README.md][1]

[1]: metasploit/README.md
