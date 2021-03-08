#!/usr/bin/env python3

import argparse
from mapping_driver import MappingDriver
from utils.utils import file_path, dir_path
from prettytable import PrettyTable


parser = argparse.ArgumentParser(description='Validates mapping files and produces various mapping visualizations.')
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
    argument('--mapping-dir', help='Path to the directory containing the mapping files',
        default="../mappings", required=False, type=dir_path),
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
        if args.mapping_dir and args.mapping_dir != "../mappings":
            raise argparse.ArgumentTypeError(
                'Specifying tags is mutually exclusive with --mapping-file argument')
        if not args.title:
            raise argparse.ArgumentTypeError('Specifying tags requires the --title argument')
    if args.mapping_file:
        if not args.output:
            raise argparse.ArgumentTypeError(
                'The --mapping-file parameter also requires the --output parameter be specified')

    if args.tag:
        mappings = mapping_driver.query_mapping_files(args.tag, args.relationship)
        mapping_files = [mapping.path for mapping in mappings]
        mapping_files = mapping_driver.load_mapping_files_as_unit(mapping_files)
        options["title"] = args.title
        options["description"] = args.description
    elif args.mapping_file:
        mapping_driver.load_mapping_file(args.mapping_file)
    elif args.mapping_dir:
        mapping_driver.load_mapping_dir(args.mapping_dir)
    else:
        raise argparse.ArgumentTypeError(
            "One of --tags --mapping-file or mapping-dir is required")


    if not args.skip_validation:
        mapping_driver.validate_mapping_files()

    mapping_driver.visualize(args.visualizer, args.output, options)


@subcommand()
def techniques_json(args):
    """Output a JSON file of ATT&CK tactics and techniques"""
    mapping_driver.output_attack_json()


@subcommand([
    argument('--mapping-dir', help='Path to the directory containing the mapping files',
        default="../mappings", required=False, type=dir_path),
    argument('--mapping-file', help='Path to the mapping file', required=False, type=file_path)
    ])
def validate(args):
    if args.mapping_file:
        mapping_driver.load_mapping_file(args.mapping_file)
    else:
        mapping_driver.load_mapping_dir(args.mapping_dir)
    mapping_driver.validate_mapping_files()


@subcommand([
    argument('--mapping-dir', help='Path to the directory containing the mapping files',
        default="../mappings", required=False, type=dir_path),
    argument("--skip-validation", help="Skip validation when visualizing mapping(s)",
        required=False, default=False, action="store_true")
    ])
def rebuild_mappings(args):
    mapping_driver.load_mapping_dir(args.mapping_dir)
    mapping_driver.rebuild_mappings(args.skip_validation)


@subcommand([
    argument('--tag', help="Return mappings with the specified tag", action="append", required=False),
    argument('--relationship', help="Relationship between tags", required=False, default="OR", choices = ["OR","AND"]),
    ])
def list_mappings(args):
    table = PrettyTable(["Name", "Mapping File", "Tag(s)", "Description"])
    table.align["Name"] = "l"
    table.align["Mapping File"] = "l"
    table.align["Tag(s)"] = "l"
    filter_tags = args.tag if args.tag else []
    mappings = mapping_driver.query_mapping_files(filter_tags, args.relationship)
    for mapping in mappings:
        tags = [tag.name for tag in mapping.tags]
        if filter_tags:
            tags = list(set(tags) & set(filter_tags))
            description = (mapping.description[:80] + "...") if len(mapping.description) > 80 else mapping.description
            table.add_row([mapping.name, mapping.path, ",\n".join(tags), description])
    
    print(table)


if __name__ == "__main__":
    args = parser.parse_args()
    if args.subcommand is None:
        parser.print_help()
    else:
        args.func(args)