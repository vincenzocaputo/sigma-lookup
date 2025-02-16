import os
import yaml
import re
import argparse
import json
import sys
import yaml

from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from src.parser import sigma_parser


if __name__ == "__main__":
    console = Console()
    parsed_file = 'cache/cache.json'
    if not os.path.isfile(parsed_file):
        console.print("> [orange3]Cache file is missing. Attempting to create a new cache...")
        os.makedirs('/'.join(parsed_file.split('/')[:-1]), exist_ok=True)
        if sigma_parser('sigma/rules', parsed_file):
            console.print("> [green]Cache file created.")

    with open(parsed_file, 'r') as fd:
        rules = json.load(fd)

    products = set( r['product'] for _, r in rules.items() if r['product'])

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--id", type=str, help="Get Sigma Rule by ID")
    parser.add_argument("-t", "--technique", type=str, help="Technique to lookup")

    tactis_choices = ["collection", \
                        "command-and-control", \
                        "credential-access", \
                        "defense-evasion", \
                        "discovery", \
                        "execution", \
                        "exfiltration", \
                        "impact", \
                        "initial-access", \
                        "lateral-movement", \
                        "persistence", \
                        "privilege-escalation", \
                        "reconnaissance", \
                        "resource-development"] 
    parser.add_argument("-T", "--tactic", type=str, help=("Tactic to lookup. Allowed values are: "+', '.join(tactis_choices)), choices=tactis_choices, metavar='')
    parser.add_argument("-p", "--product", type=str, 
                        help=("Search by Product. Allowed values are: "+', '.join(products)), 
                        choices=list(products), metavar='')
    status_values = ['stable', \
                    'test', \
                    'experimental', \
                    'deprecated', \
                    'unsupported']
    parser.add_argument("-S", "--status", nargs="+", help="Filter by status. Allowed values are: "+', '.join(status_values), choices=status_values, metavar='')
    parser.add_argument("-s", "--search", type=str, help="Search rules by free text")
    parser.add_argument("-F", "--force-caching", help="Force the caching of the detection rules.", action="store_true")
    args = parser.parse_args()
    technique = args.technique
    tactic = args.tactic
    status = args.status
    product = args.product
    search_text = args.search

    rule_id = args.id

    if args.force_caching:
        console.print("> [orange3]Caching the detection rules...")
        if sigma_parser('sigma/rules', parsed_file):
            console.print("> [green]Cache file created.")
            sys.exit(0)
        else:
            console.print("[bold][red]An error occurred during the operation. Exiting...")
            sys.exit(1)

    if rule_id:
        with open(rules[rule_id]['filepath'], 'r') as fd:
            console.print(Syntax(fd.read(), 'yaml'))
        sys.exit(0)

    if not any((technique, tactic, search_text, product, status)):
        parser.print_help()
        console.print("[bold][red] Error: You must provide at least one argument")
        sys.exit(1)

    table = Table(title="Sigma Rules", show_lines=True)
    table.add_column("Rule ID", style="cyan", no_wrap=True)
    table.add_column("Title", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    if search_text:
        table.add_column("Description", no_wrap=False)
    table.add_column("Product", no_wrap=True)
    table.add_column("Category", no_wrap=True)
    table.add_column("Tactics", style="magenta", no_wrap=True)
    table.add_column("Techniques", style="green", no_wrap=True)

    for rid, rule in rules.items():
        technique_match = False
        tactic_match = False
        search_match = False
        status_match = False
        product_match = False

        rule_title = Text(rule['title'])
        rule_description = Text(rule['description'])
        if technique:
            for t in rule['techniques']:
                if re.match(f'{technique.lower()}(?=$|\\.)', t):
                    technique_match=True
                
        else:
            technique_match = True

        if tactic:
            for t in rule['tactics']:
                if t == tactic:
                    tactic_match = True
        else:
            tactic_match = True

        if search_text:
            title_match = re.search(search_text, rule['title'], re.IGNORECASE) or False
            if title_match:
                rule_title.highlight_regex(title_match.group(0), style="red")
            descr_match = re.search(search_text, rule['description'], re.IGNORECASE) or False
            if descr_match:
                rule_description.highlight_regex(descr_match.group(0), style="red")

            search_match = any((title_match, descr_match))
        else:
            search_match = True

        if product:
            if product == rule['product']:
                product_match = True
        else:
            product_match = True

        if status:
            if any((s == rule['status'] for s in status)):
                status_match = True
        else:
            status_match = True

        if all((technique_match, tactic_match, search_match, product_match, status_match)):
            if search_text:
                table.add_row(rid, 
                                rule_title, 
                                rule['status'],
                                rule_description, 
                                rule['product'], 
                                rule['category'], 
                                '\n'.join(rule['tactics']), 
                                '\n'.join(rule['techniques']))
            else:
                table.add_row(rid, 
                                rule_title, 
                                rule['status'],
                                rule['product'], 
                                rule['category'], 
                                '\n'.join(rule['tactics']), 
                                '\n'.join(rule['techniques']))

    console.print(table)



