## Mapping CLI Tool

### Introduction

The mapping CLI tool provides functionality related to querying and visualizing the data contained in mapping files.  It supports multiple functional modes with each mode accompanied with help text.

### Install

#### Requirements:
- Python 3

It is best practice to create an isolated [Python virtual environment](https://docs.python.org/3/library/venv.html) using the `venv` standard library module to manage the dependencies between your different Python projects.

```
1.  Change directory (cd) into the tools directory.
1.  Create the virtual environment:  python3 -m venv venv
1.  Activate the environment:  source ./venv/bin/activate
1.  Install the project requirements:  pip install -r requirements.txt
```

### Usage
```
➜  ./mapping_cli.py -h

usage: mapping_cli.py [-h]
                      {visualize,techniques_json,validate,rebuild_mappings,list_mappings,list_scores}
                      ...

Provides functionality related to querying and visualizing the data contained in mapping files.

optional arguments:
  -h, --help            show this help message and exit

subcommands:
  Specify the subcommand with -h option for help (Ex: ./mapping_cli visualize -h)

  {visualize,techniques_json,validate,rebuild_mappings,list_mappings,list_scores}
```

### Validate
```
➜  mapping_cli.py validate -h
usage: mapping_cli.py validate [-h] [--mapping-dir MAPPING_DIR]
                               [--mapping-file MAPPING_FILE]

Validates a mapping file or all mapping files in a directory

optional arguments:
  -h, --help            show this help message and exit
  --mapping-dir MAPPING_DIR
                        Path to the directory containing the mapping files
  --mapping-file MAPPING_FILE
                        Path to the mapping file
  --tags-file TAGS_FILE
                        Path to the file containing the list of valid tags
```
#### Examples
-  Validate all mapping files in the default mappings directory (```../mappings```):</br>
  ```./mapping_cli.py validate```
-  Validate all mapping files in a specified directory:</br>
```./mapping_cli.py validate --mapping-dir <mapping directory>```  
-  Validate a particular mapping file:</br>
```./mapping_cli.py validate --mapping-file ../mappings/Azure/JustInTimeVMAccess.yaml```

#### Visualize
```
➜  mapping_cli.py visualize -h
usage: mapping_cli.py visualize [-h] --visualizer
                                {AttackNavigator,MarkdownSummary}
                                [--mapping-dir MAPPING_DIR]
                                [--mapping-file MAPPING_FILE]
                                [--output OUTPUT] [--skip-validation]
                                [--tag TAG] [--title TITLE]
                                [--description DESCRIPTION]
                                [--relationship {OR,AND}]
                                [--include-aggregates] [--include-html]

Build visualizations from mapping file(s)

optional arguments:
  -h, --help            show this help message and exit
  --visualizer {AttackNavigator,MarkdownSummary}
                        The name of the visualizer that will generate the
                        visualizations
  --mapping-dir MAPPING_DIR
                        Path to the directory containing the mapping files
  --mapping-file MAPPING_FILE
                        Path to the mapping file
  --output OUTPUT       Path to the directory were the visualizations will be
                        written
  --skip-validation     Skip validation when visualizing mapping(s)
  --tag TAG             Return mappings with the specified tag, this will
                        utilize the db rather than traversing the file system
  --title TITLE         Title of the visualization
  --description DESCRIPTION
                        Description of the visualization
  --relationship {OR,AND}
                        Relationship between tags
  --include-aggregates  When generating a visualization for mappings, generate
                        it for each tag and platform also. This depends on
                        visualizer support.
  --include-html        When generating a visualization, if supported,
                        generate an HTML version too.
```
##### Examples
-  Generate [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layers for each mapping file in the default mappings directory (```../mappings```):</br>
  ```./mapping_cli.py visualize --visualizer AttackNavigator```
-  Generate an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer for a particular mapping file and save the layer in the `/tmp/my_layers` directory:</br>
```./mapping_cli.py visualize --visualizer AttackNavigator --mapping-file ../mappings/Azure/IdentityProtection.yaml --output /tmp/my_layers```
-  Generate an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer for all mappings with the specified tag:</br>
```./mapping_cli.py visualize --visualizer AttackNavigator --tag "Azure Defender" --title "Azure Defender" --skip-validation```
-  Generate [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layers for each mapping file in the default mappings directory (```../mappings```).  In addition, generate a layer for each tag and an aggregate layer for all mapping files for the platform:</br>
```./mapping_cli.py visualize --visualizer AttackNavigator --skip-validation --include-aggregates```
-  Generate a Markdown Summary view for all mapping files in the default mappings directory (```../mappings```).  In addition, generate an HTML version of the view:</br>
```./mapping_cli.py visualize --visualizer MarkdownSummary --skip-validation --include-html```


List Mappings:
```.env
➜  mapping_cli.py list_mappings -h
usage: mapping_cli.py list_mappings [-h] [--tag TAG] [--relationship {OR,AND}]
                                    [--width WIDTH] [--name NAME]
                                    [--platform PLATFORM]

optional arguments:
  -h, --help            show this help message and exit
  --tag TAG             Return mappings with the specified tag
  --relationship {OR,AND}
                        Relationship between tags
  --width WIDTH         Set the width of the Comments column
  --name NAME           Filter the returned mappings by a substring of the
                        control name.
  --platform PLATFORM   Filter by mapping platform (e.g. Azure).
```

List Scores:
```
➜  mapping_cli.py list_scores -h
usage: mapping_cli.py list_scores [-h] [--category {Protect,Detect,Respond}]
                                  [--attack-id ATTACK_ID] [--tactic TACTIC]
                                  [--control CONTROL] [--platform PLATFORM]
                                  [--score {Minimal,Partial,Significant}]
                                  [--width WIDTH]
                                  [--level {Technique,Sub-technique}]
                                  [--tag TAG]

optional arguments:
  -h, --help            show this help message and exit
  --category {Protect,Detect,Respond}
                        Filter by score category
  --attack-id ATTACK_ID
                        Filter by ATT&CK ID (specify Technique [default] or
                        Sub-technique using --level parameter)
  --tactic TACTIC       Filter by ATT&CK tactic name
  --control CONTROL     Filter by a control (name)
  --platform PLATFORM   Filter by mapping platform (e.g. Azure).
  --score {Minimal,Partial,Significant}
                        Filter by mapping score
  --width WIDTH         Set the width of the Comments column
  --level {Technique,Sub-technique}
                        Return technique data or sub-technique data
  --tag TAG             Return mappings with the specified tag. This does a
                        LIKE search for exact match, surround w/ quotes (e.g.
                        '"Azure Defender"'
```