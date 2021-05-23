## Mapping CLI Tool

### Introduction

The mapping CLI tool provides functionality related to querying and visualizing the data contained in mapping files.  It supports multiple functional modes with each mode accompanied with help text.

### Install

#### Requirements:
- Python 3

It is best practice to create an isolated [Python virtual environment](https://docs.python.org/3/library/venv.html) using the `venv` standard library module to manage the dependencies between your different Python projects.

1.  Change directory (cd) into the tools directory.
1.  Create the virtual environment:  `python3 -m venv venv`
1.  Activate the environment:  `source ./venv/bin/activate`
1.  Install the project requirements:  `pip install -r requirements.txt`

### Usage
```
./mapping_cli.py -h

usage: mapping_cli.py [-h]
                      {visualize,techniques_json,validate,rebuild_mappings,list_mappings,list_scores}
                      ...

Provides functionality related to querying and visualizing the data contained in mapping files.

optional arguments:
  -h, --help            show this help message and exit

subcommands:
  Specify the subcommand with -h option for help (Ex: ./mapping_cli visualize -h)

  {validate,visualize,rebuild_mappings,list_mappings,list_scores}
```

### Validate Subcommand
```
mapping_cli.py validate -h
usage: mapping_cli.py validate [-h] [--mapping-dir MAPPING_DIR]
                               [--mapping-file MAPPING_FILE]

Validates a mapping file or all mapping files in a directory.

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
```./mapping_cli.py validate --mapping-dir /home/mapper/my_mappings_dir```  
-  Validate a particular mapping file:</br>
```./mapping_cli.py validate --mapping-file ../mappings/Azure/JustInTimeVMAccess.yaml```

### Visualize Subcommand
```
mapping_cli.py visualize -h
usage: mapping_cli.py visualize [-h] --visualizer
                                {AttackNavigator,MarkdownSummary}
                                [--mapping-dir MAPPING_DIR]
                                [--mapping-file MAPPING_FILE]
                                [--output OUTPUT] [--skip-validation]
                                [--tag TAG] [--title TITLE]
                                [--description DESCRIPTION]
                                [--relationship {OR,AND}]
                                [--include-aggregates] [--include-html]

Build visualizations from mapping file(s).

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
#### Examples
-  Generate [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layers for each mapping file in the default mappings directory (```../mappings```):</br>
  ```./mapping_cli.py visualize --visualizer AttackNavigator```
-  Generate an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer for a particular mapping file and save the layer in the `/tmp/my_layers` directory:</br>
```./mapping_cli.py visualize --visualizer AttackNavigator --mapping-file ../mappings/Azure/IdentityProtection.yaml --output /tmp/my_layers```
-  Generate an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer for all mappings with the specified tag:</br>
```./mapping_cli.py visualize --visualizer AttackNavigator --tag "Azure Defender" --title "Azure Defender" --skip-validation```
-  Generate [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layers for each mapping file in the default mappings directory (```../mappings```).  In addition, generate a layer for each tag and an aggregate layer for all mapping files for each platform:</br>
```./mapping_cli.py visualize --visualizer AttackNavigator --skip-validation --include-aggregates```
-  Generate a Markdown Summary view of all mapping files in the default mappings directory (```../mappings```).  In addition, generate an HTML version of the view:</br>
```./mapping_cli.py visualize --visualizer MarkdownSummary --skip-validation --include-html```


### Rebuild Mappings Subcommand

```
usage: mapping_cli.py rebuild_mappings [-h] [--mapping-db MAPPING_DB]
                                       [--mapping-dir MAPPING_DIR]
                                       [--skip-attack] [--skip-validation]

Builds the mapping database used to provide the query capabilities of the
list_mappings and list_scores subcommands.

optional arguments:
  -h, --help            show this help message and exit
  --mapping-db MAPPING_DB
                        Path to the mapping.db file to generate
  --mapping-dir MAPPING_DIR
                        Path to the directory containing the mapping files
  --skip-attack         Rebuild an existing mapping.db by just rebuilding the 
                        mapping data (and reuse the already built ATT&CK data)
  --skip-validation     Skip validation of discovered mapping files, just
                        import them into the db.
```

#### Examples
- Scan all the mapping files in the default mappings directory (`../mappings`) and build a SQLite database containing the mapping data.  Produces the `mapping.db` file in the current directory:</br>
  ```
  ./mapping_cli.py rebuild_mappings
  ```


### List Mappings Subcommand
```
usage: mapping_cli.py list_mappings [-h] [--mapping-db MAPPING_DB] [--tag TAG]
                                    [--relationship {OR,AND}] [--width WIDTH]
                                    [--name NAME] [--platform PLATFORM]

List mapping files by name, tag and/or platform.

Requires the mapping database to be built using the rebuild_mappings command.

optional arguments:
  -h, --help            show this help message and exit
  --mapping-db MAPPING_DB
                        Path to the mapping.db file
  --tag TAG             Return mappings with the specified tag
  --relationship {OR,AND}
                        Relationship between tags (default OR)
  --width WIDTH         Set the width of the Comments column
  --name NAME           Filter the returned mappings by a substring of the
                        control name.
  --platform PLATFORM   Filter by mapping platform (e.g. Azure).
```
#### Examples
- List the mapping file of all controls that have "Defender" in the control name and limit the width of the comments section to 40 characters per line:
  ```
  ./mapping_cli.py list_mappings --name Defender --width 40
  ```
- List the mapping file of all controls that have the tag "Linux" and are from the Azure platform:
  ```
  ./mapping_cli.py list_mappings --tag Linux --platform Azure
  ```
- List the mapping file of all controls that have the tag "Linux" and the tag "Azure Security Center":
  ```
  ./mapping_cli.py list_mappings --tag Linux --tag "Azure Security Center" --relationship AND
  ```

###  List Scores Subcommand
```
usage: mapping_cli.py list_scores [-h] [--mapping-db MAPPING_DB]
                                  [--category {Protect,Detect,Respond}]
                                  [--attack-id ATTACK_ID] [--tactic TACTIC]
                                  [--control CONTROL] [--platform PLATFORM]
                                  [--score {Minimal,Partial,Significant}]
                                  [--width WIDTH]
                                  [--level {Technique,Sub-technique}]
                                  [--tag TAG]

Query mapping data by various filters and return a table consisting of the
following columns: Control Name, Mapping File Path, Technique/Sub-technique ID
& Name, Score, Score comment. 

Requires the mapping database to be built using the rebuild_mappings subcommand.

optional arguments:
  -h, --help            show this help message and exit
  --mapping-db MAPPING_DB
                        Path to the mapping.db file
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

#### Examples
- Return a table with a row for each technique in a mapping file that has a Protect score category:
  ```
  ./mapping_cli.py list_scores --category Protect
  ```
- Return a table with a row for each mapping file that has a Protect score category for technique T1078 Valid Accounts:
  ```
  ./mapping_cli.py list_scores --category Protect --attack-id T1078
  ```
- Return a table with a row for each mapping file that has a Protect score category for technique T1078 Valid Accounts or technique T1578 Modify Cloud Compute Infrastructure:
  ```
  ./mapping_cli.py list_scores --category Protect --attack-id T1078 --attack-id T1578
  ```
- Return a table with a row for each mapping file that has a Protect score category for sub-techniques of T1078 Valid Accounts.  Displays the sub-technique scores instead of technique scores:
  ```
  ./mapping_cli.py list_scores --category Protect --attack-id T1078 --level Sub-technique
  ```
- Return a table with a row for each Azure mapping file that has a Protect score category with a Minimal or Significant score.  Limit the width of the score comments column to 40 characters:
  ```
  ./mapping_cli.py list_scores --category Protect --platform Azure --score Minimal --score Significant --width 40
  ```
- Return a table with a row for each score category for controls with a name that contains the "Identity Protection" that provide a mapping for technique T1078 Valid Accounts:

  ```
  ./mapping_cli.py list_scores  --attack-id T1078 --level Technique --control "Identity Protection"
  ```
