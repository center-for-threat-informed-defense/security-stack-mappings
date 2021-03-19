Under Construction ...

Setup:  

1.  cd tools directory
1.  Install Python 3
1.  Create virtual environment:  python3 -m venv ~/Development/cloud_security_stack_mappings
1.  Activate environment:  source ~/Development/cloud_security_stack_mappings/bin/activate
1.  Install requirements:  pip install -r requirements.txt


Examples:
1.  Run the command:  ./mapping_cli.py validate
1.  More examples:   ./mapping_cli.py list_mappings
1.  More examples:   ./mapping_cli.py rebuild_mappings


Make sure to run rebuild_mappings command before these commands (that have tag arguments)
1.  More examples:   ./mapping_cli.py list_mappings --tag "Azure Defender"
1.  More examples:  ./mapping_cli.py list_mappings --tag "Azure Defender" --tag "Azure Sentinel" --relationship AND
1.  More examples:  ./mapping_cli.py list_mappings --tag "Azure Defender" --tag "Azure Sentinel" --relationship OR
1.  Help:  ./mapping_cli.py visualize -h
1.  Another example:  ./mapping_cli.py visualize --visualizer AttackNavigator  --skip-validation
1.  Another example:  ./mapping_cli.py visualize --visualizer AttackNavigator --tag "Azure Defender" --title "Azure Defender" --skip-validation

New functionality to review scores values and comments
1. ./mapping_cli.py list_scores --category Protect
1. ./mapping_cli.py list_scores --category Protect --level Sub-technique
1. ./mapping_cli.py list_scores --category Protect --level Technique --width 100
