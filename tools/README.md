## Usage

### CLI

To install: 
```
1.  cd tools directory
2.  Install Python 3
3.  Create virtual environment:  python3 -m venv ~/Development/cloud_security_stack_mappings
4.  Activate environment:  source ~/Development/cloud_security_stack_mappings/bin/activate
5.  Install requirements:  pip install -r requirements.txt
```

To use:
```
➜  ./mapping_cli.py -h

usage: mapping_cli.py [-h]
                      {visualize,techniques_json,validate,rebuild_mappings,list_mappings,list_scores}
                      ...

Validates mapping files and produces various mapping visualizations.

optional arguments:
  -h, --help            show this help message and exit

subcommands:
  Specify the subcommand with -h option for help (Ex: ./mapping_cli
  visualize -h)

  {visualize,techniques_json,validate,rebuild_mappings,list_mappings,list_scores}
```

Vizualize: 
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

Validate:
```
➜  mapping_cli.py validate -h
usage: mapping_cli.py validate [-h] [--mapping-dir MAPPING_DIR]
                               [--mapping-file MAPPING_FILE]

optional arguments:
  -h, --help            show this help message and exit
  --mapping-dir MAPPING_DIR
                        Path to the directory containing the mapping files
  --mapping-file MAPPING_FILE
                        Path to the mapping file
```

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