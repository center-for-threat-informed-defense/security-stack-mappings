Under Construction ...

Example:  

1.  cd tools directory
1.  Install Python 3
1.  Create virtual environment:  python3 -m venv ~/Development/cloud_security_stack_mappings
1.  Activate environment:  source ~/Development/cloud_security_stack_mappings/bin/activate
1.  Install requirements:  pip install -r requirements.txt
1.  Run the command:  ./mapping_cli.py --action visualize --visualizer Markdown --output output
1.  Another example:  ./mapping_cli.py --action visualize --visualizer AttackNavigator  --skip-validation
1.  Validation of mappings:  ./mapping_cli.py --action validate
