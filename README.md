# SG Sesame
<p align="center">

<a href="https://pypi.python.org/pypi/sg_sesame">
<img src="https://img.shields.io/pypi/v/sg_sesame.svg" /></a>
<a href="https://travis-ci.org/stopmachine/sg_sesame"><img src="https://travis-ci.org/stopmachine/sg_sesame.svg?branch=master" /></a>
</p>
Open ports in Security Groups for your current IP address

## Installation
Install globally using [pipx](https://github.com/pipxproject/pipx/):

`pipx install sg-sesame`

## Usage
### Quickstart
Just install and run:

`sg-sesame --port 22 --add`

After the first run, you can omit the `--add` flag: `sg-sesame --port 22`.

If you have more than one Security Group with a rule for port 22, you will be asked to choose from a list.

### Advanced usage
```
$ sg-sesame --help

Usage: sg-sesame [OPTIONS]

Options:
  --port INTEGER     [required]
  --note TEXT        Description of the rule to be added/updated. If omitted,
                     the machine hostname will be used.

  --add / --no-add   If not specified, will try to update an existing rule
                     that has matching `note`, `port` and `protocol`.
                     Otherwise will add a new rule.

  --group-name TEXT  If specified, the rule will be added to the Security
                     Group with this name. Otherwise will prompt the user to
                     select a SG.

  --protocol TEXT    Protocol to use for the rule  [default: tcp]
  --profile TEXT     AWS profile to use  [default: default]
  --region TEXT      AWS Region to connect to
  --help             Show this message and exit.
```

## Credits
This package was created with Cookiecutter and the `cs01/cookiecutter-pypackage` project template.

[Cookiecutter](https://github.com/audreyr/cookiecutter)

[cs01/cookiecutter-pypackage](https://github.com/cs01/cookiecutter-pypackage)
