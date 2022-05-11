# Security Stack Mappings: Developers' Guide

## Setup

This repository requires Python 3. After cloning, run the following commands to
install dependencies:

```shell
$ cd tools/
$ python3 -m venv --upgrade-deps venv
Requirement already satisfied: pip in ./venv/lib/python3.9/site-packages (22.0.4)
Requirement already satisfied: setuptools in ./venv/lib/python3.9/site-packages (60.10.0)
Collecting setuptools
  Using cached setuptools-62.1.0-py3-none-any.whl (1.1 MB)
Installing collected packages: setuptools
  Attempting uninstall: setuptools
    Found existing installation: setuptools 60.10.0
    Uninstalling setuptools-60.10.0:
      Successfully uninstalled setuptools-60.10.0
Successfully installed setuptools-62.1.0
$ source venv/bin/activate
(venv) $ pip install -r requirements.txt
Collecting antlr4-python3-runtime==4.8
  Using cached antlr4_python3_runtime-4.8-py3-none-any.whl
Collecting attrs==20.3.0
  Using cached attrs-20.3.0-py2.py3-none-any.whl (49 kB)
...snip...
Installing collected packages: wcwidth, pytz, mdutils, certifi, antlr4-python3-runtime, urllib3, SQLAlchemy, six, simplejson, PyYAML, pyrsistent, prettytable, Markdown, idna, chardet, attrs, stix2-patterns, requests, pyaml, jsonschema, taxii2-client, stix2
  Running setup.py install for mdutils ... done
  Running setup.py install for simplejson ... done
  Running setup.py install for pyrsistent ... done
Successfully installed Markdown-3.1.1 PyYAML-5.4.1 SQLAlchemy-1.3.22 antlr4-python3-runtime-4.8 attrs-20.3.0 certifi-2020.12.5 chardet-4.0.0 idna-2.10 jsonschema-3.2.0 mdutils-1.3.0 prettytable-2.1.0 pyaml-20.4.0 pyrsistent-0.17.3 pytz-2020.5 requests-2.25.1 simplejson-3.17.2 six-1.15.0 stix2-2.1.0 stix2-patterns-1.3.2 taxii2-client-2.2.2 urllib3-1.26.5 wcwidth-0.2.5
```

## Mapping CLI

The script `mapping_cli.py` supports the workflow to develop, validate, and
publish mappings. Here are some common use cases.

**Validate mappings:**

Check the YAML mapping files for correctness.

```shell
./mapping_cli.py validate --mapping-dir <directory of *.yml files>
```

**Publish to HTML:**

Convert YAML mapping files into the HTML version that we publish.

```shell
./mapping_cli.py visualize --mapping-dir <directory of *.yml files> --visualizer MarkdownSummary --include-html
```

**Mappings Database:**

There are several commands for importing the mappings into a SQLite database and
running some common queries on that database. The first command creates the
database and imports the mappings into it.

```shell
./mapping_cli.py rebuild_mappings --mapping-dir <directory of *.yml files>
```

Display a summary of the controls that are mapped:

```shell
./mapping_cli.py list_mappings
```

Display the mappings of controls to techniques, including the scores:

```shell
./mapping_cli.py list_scores --platform <AWS|Azure|GCP>
```

**JSON Export:**

Export a JSON summary of the ATT&CK techniques that are used in the mappings.

```shell
./mapping_cli.py techniques_json
```
