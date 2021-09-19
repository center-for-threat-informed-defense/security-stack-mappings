#!/usr/bin/env python3

import os
import argparse
from mapping_driver import MappingDriver
from utils.utils import file_path, dir_path, chunkstring, get_project_root
from prettytable import PrettyTable
from pathlib import Path

parser = argparse.ArgumentParser(description='Provides functionality related to querying and '
    'visualizing the data contained in mapping files.')
subparsers = parser.add_subparsers(dest="subcommand", description="Specify the subcommand with -h option for help"
    " (Ex:  ./mapping_cli visualize -h)")
mapping_driver = MappingDriver()


def argument(*name_or_flags, **kwargs):
    """Convenience function to properly format arguments to pass to the subcommand decorator. """
    return (list(name_or_flags), kwargs)


def subcommand(args=[], parent=subparsers):
    def decorator(func):
        parser = parent.add_parser(func.__name__, description=func.__doc__)
        for arg in args:
            parser.add_argument(*arg[0], **arg[1])
        parser.set_defaults(func=func)
    return decorator


@subcommand([
    argument("--visualizer", help="The name of the visualizer that will generate the visualizations", 
        required=True,choices=mapping_driver.get_visualizer_names()),
    argument('--mapping-dir', help='Path to the directory containing the mapping files', required=False, type=dir_path),
    argument('--no-recurse', help='Do not search nested directories for mapping files',
        required=False, default=False, action="store_true"),
    argument('--mapping-file', help='Path to the mapping file', required=False, type=file_path),
    argument("--output", help="Path to the directory were the visualizations will be written",
        required=False, type=dir_path),
    argument("--skip-validation", help="Skip validation when visualizing mapping(s)",
        required=False, default=False, action="store_true"),
    argument('--tag', help="Return mappings with the specified tag, this will utilize the db "
        "rather than traversing the file system", action="append", required=False),
    argument('--title', help="Title of the visualization", required=False),
    argument('--description', help="Description of the visualization", required=False, default=""),
    argument('--relationship', help="Relationship between tags", required=False, default="OR", choices = ["OR","AND"]),
    argument('--include-aggregates', help='When generating a visualization type for mappings, also generate it for each tag and' 
        ' platform also.  This depends on visualizer support.', default=False, required=False, action="store_true"),
    argument('--include-html', help='When generating a visualization, if supported, generate an HTML version too.',
        default=False, required=False, action="store_true"),
    argument('--mapping-db', help='Path to the mapping.db file to generate', default="mapping.db",
        required=False),
    ])
def visualize(args):
    """Build visualizations from mapping file(s)"""

    options = {}
    if not args.visualizer:
        raise argparse.ArgumentTypeError(
            'Visualize action with a mapping-file specified requires the --visualizer parameter be specified')
    if args.tag:
        if args.mapping_file:
            raise argparse.ArgumentTypeError(
                'Specifying tags is mutually exclusive with --mapping-file argument')
        if args.mapping_dir:
            raise argparse.ArgumentTypeError(
                'Specifying tags is mutually exclusive with --mapping-dir argument')
        if not args.title:
            raise argparse.ArgumentTypeError('Specifying tags requires the --title argument')
        if not args.mapping_db:
            raise argparse.ArgumentTypeError('Specifying tags requires the --mapping-db argument')
    if args.mapping_file:
        if not args.output:
            raise argparse.ArgumentTypeError(
                'The --mapping-file parameter also requires the --output parameter be specified')

    options["include-aggregates"] = False
    options["include-html"] = args.include_html
    if args.tag:
        mapping_driver.set_mapping_db(args.mapping_db)
        mappings = mapping_driver.query_mapping_files(args.tag, args.relationship, None, None)
        mapping_files = [mapping.path for mapping in mappings]
        if not mapping_files:
            exit("No mappings returned.  Is the database initialized?")
        mapping_files = mapping_driver.load_mapping_files_as_unit(mapping_files)
        options["title"] = args.title
        options["description"] = args.description
    elif args.mapping_file:
        mapping_driver.load_mapping_file(args.mapping_file)
    elif args.mapping_dir:
        options["include-aggregates"] = args.include_aggregates
        mapping_driver.load_mapping_dir(args.mapping_dir, args.no_recurse)
    else:
        options["include-aggregates"] = args.include_aggregates
        root_dir = get_project_root()
        mapping_driver.load_mapping_dir(f'{root_dir}/mappings', args.no_recurse)


    if not args.skip_validation:
        mapping_driver.validate_mapping_files()

    mapping_driver.visualize(args.visualizer, args.output, options)


@subcommand()
def techniques_json(args):
    """Output a JSON file of ATT&CK tactics and techniques"""
    mapping_driver.output_attack_json()


@subcommand([
    argument('--mapping-dir', help='Path to the directory containing the mapping files',
        required=False, type=dir_path),
    argument('--no-recurse', help='Do not search nested directories for mapping files',
        required=False, default=False, action="store_true"),
    argument('--mapping-file', help='Path to the mapping file', required=False, type=file_path),
    argument('--tags-file', help='Path to the file containing the list of valid tags',
        required=False, type=file_path)
    ])
def validate(args):
    """Validates a mapping file or all mapping files in a directory"""
    if args.mapping_file:
        mapping_driver.load_mapping_file(args.mapping_file)
    elif args.mapping_dir:
        mapping_driver.load_mapping_dir(args.mapping_dir, args.no_recurse)
    else:
        root_dir = get_project_root()
        mapping_driver.load_mapping_dir(f'{root_dir}/mappings', args.no_recurse)

    if args.tags_file:
        mapping_driver.load_specified_tags(args.tags_file)

    if mapping_driver.validate_mapping_files():
        print("\n\nValidation Succeeded!")
    else:
        print("\n\nValidation Failed!")
        exit(1)


@subcommand([
    argument('--mapping-db', help='Path to the mapping.db file to generate', default="mapping.db",
        required=False),
    argument('--mapping-dir', help='Path to the directory containing the mapping files',
        required=False, type=dir_path),
    argument('--no-recurse', help='Do not search nested directories for mapping files',
        required=False, default=False, action="store_true"),
    argument('--skip-attack', help='Rebuild an existing mapping.db by just rebuilding the mapping data'
        ' (and reuse the already built ATT&CK data)',
        default=False, required=False, action="store_true"),
    argument("--skip-validation", help="Skip validation of discovered mapping files, just import them into the db.",
        required=False, default=False, action="store_true")
    ])
def rebuild_mappings(args):
    """Builds the mapping database used to provide the query capabilities of the list_mappings and list_scores modes"""
    if args.mapping_dir:
        mapping_driver.load_mapping_dir(args.mapping_dir, args.no_recurse)
    else:
        root_dir = get_project_root()
        mapping_driver.load_mapping_dir(f'{root_dir}/mappings', args.no_recurse)

    mapping_driver.set_mapping_db(args.mapping_db)
    mapping_driver.rebuild_mappings(args.skip_validation, args.skip_attack)


@subcommand([
    argument('--mapping-db', help='Path to the mapping.db file', default="mapping.db", required=False, type=file_path),
    argument('--tag', help="Return mappings with the specified tag", action="append", required=False),
    argument('--relationship', help="Relationship between tags (default OR)", required=False, default="OR", choices = ["OR","AND"]),
    argument('--width', help="Set the width of the Comments column", type=int, required=False, default=80),
    argument('--name', help="Filter the returned mappings by a substring of the control name.", action="append", required=False),
    argument('--platform', help="Filter by mapping platform (e.g. Azure).", action="append", required=False),
    ])
def list_mappings(args):
    """List mapping files by name, tag and/or platform.
    Requires the mapping database to be built using the rebuild_mappings subcommand."""

    table = PrettyTable(["No.", "Name", "Mapping File", "Tag(s)", "Description"])
    table.align["No."] = "l"
    table.align["Name"] = "l"
    table.align["Mapping File"] = "l"
    table.align["Tag(s)"] = "l"
    table.align["Description"] = "l"
    filter_tags = args.tag if args.tag else []

    mapping_driver.set_mapping_db(args.mapping_db)
    mappings = mapping_driver.query_mapping_files(filter_tags, args.relationship, args.name, args.platform)
    num_rows = 0
    for mapping in mappings:
        tags = [tag.name for tag in mapping.tags]
        if filter_tags:
            tags = list(set(tags) & set(filter_tags))
        description = "\n ".join(chunkstring(mapping.description, args.width))
        path = Path(mapping.path)
        path = "\n ".join(chunkstring(f"{path.parent.name}/{path.name}", 40))
        name = "\n ".join(chunkstring(mapping.name, 30))
        table.add_row([(num_rows + 1), name, path, ",\n".join(tags), description])
        num_rows +=1
    
    print(table)
    print(f"Total Rows:  {num_rows}")


@subcommand([
    argument('--mapping-db', help='Path to the mapping.db file', default="mapping.db", required=False, type=file_path),
    argument('--category', help="Filter by score category", \
        action="append", required=False,choices = ["Protect","Detect", "Respond"]),
    argument('--attack-id', help="Filter by ATT&CK ID (specify Technique [default] or Sub-technique using --level parameter)", \
        action="append", required=False),
    argument('--tactic', help="Filter by ATT&CK tactic name", action="append", required=False),
    argument('--control', help="Filter by a control (name)", action="append", required=False),
    argument('--platform', help="Filter by mapping platform (e.g. Azure).", action="append", required=False),
    argument('--score', help="Filter by mapping score", action="append", choices = ["Minimal", "Partial", "Significant"], \
         required=False),
    argument('--width', help="Set the width of the Comments column", type=int, required=False, default=80),
    argument('--level', help="Return technique data or sub-technique data", required=False, \
        default="Technique", choices = ["Technique","Sub-technique"]),
    argument('--tag', help="Return mappings with the specified tag. "
        "This does a LIKE search for exact match, surround w/ quotes (e.g. '\"Azure Defender\"'", 
        action="append", required=False),
    ])
def list_scores(args):
    """Query mapping data by various filters and return a table consisting of the following columns:
    Control Name, Mapping File Path, Technique/Sub-technique ID & Name, Score, Score comment.
    Requires the mapping database to be built using the rebuild_mappings subcommand."""
    filter_category = args.category if args.category else []
    attack_ids = args.attack_id if args.attack_id else []
    controls = args.control if args.control else []
    scores = list(set(args.score if args.score else []))
    platforms = args.platform if args.platform else []
    tactics = args.tactic if args.tactic else []
    tags = args.tag if args.tag else []

    if not controls and not filter_category and not attack_ids and not scores and not platforms and not tactics and not tags:
        raise argparse.ArgumentTypeError('At least one filter option must be provided: '
            '--control, --category, --score, --platform, --tactic or --attack-id or --tag parameters is required')
        
    if args.level == "Technique":
        table = PrettyTable(["No.", "Name", "Mapping File", "Technique", "Category", "Score", "Comments"])
    else:
        table = PrettyTable(["No.", "Name", "Mapping File", "Sub-technique", "Category", "Score", "Comments"])

    table.align["No."] = "l"
    table.align["Name"] = "l"
    table.align["Mapping File"] = "l"
    table.align["Technique"] = "l"
    table.align["Sub-technique"] = "l"
    table.align["Comments"] = "l"
    table.align["Category"] = "l"
    table.align["Score"] = "l"

    mapping_driver.set_mapping_db(args.mapping_db)
    data = mapping_driver.query_mapping_file_scores(filter_category, attack_ids, \
        controls, args.level, platforms, scores, tactics, tags)
    num_rows = 0
    for mapping, attack_entity, score in data:
        attack_entity_info = "\n ".join(chunkstring(f"{attack_entity.attack_id} {attack_entity.name}", 25))
        path = Path(mapping.path)
        if path.parent.name:
            path = "\n ".join(chunkstring(f"{path.parent.name}/{path.name}", 40))
        else:
            path = "\n ".join(chunkstring(f"{path.name}", 40))
        description = "\n ".join(chunkstring(score.comments, args.width))
        name = "\n ".join(chunkstring(mapping.name, 30))
        table.add_row([num_rows + 1, name, path, attack_entity_info, score.category, score.value, description])
        num_rows +=1
    
    if filter_category:
        table.del_column("Category")

    print(table)
    print(f"Total Rows:  {num_rows}")


if __name__ == "__main__":
    args = parser.parse_args()
    if args.subcommand is None:
        parser.print_help()
    else:
        args.func(args)
