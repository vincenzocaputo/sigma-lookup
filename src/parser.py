import os
import yaml
import json
from rich.progress import Progress
from src import ROOT

def sigma_parser(folder, target_file):
    rules = {}
    file_count = sum(len(files) for _, _, files in os.walk(folder))
    with Progress() as progress:
        task = progress.add_task("[cyan]Processing rules...", total=file_count)

        rule_id = 1
        for root, dirs, files in os.walk(folder):
            for name in files:
                if not name.endswith(".yml"):
                    progress.update(task, advance=1)
                    continue
                filepath = os.path.join(root, name)

                with open(filepath, 'r') as fd:
                    content = yaml.safe_load(fd)
                rule = {}

                rule['title'] = content['title']
                rule['tags'] = content.get('tags', [])
                rule['status'] = content.get('status', '')
                rule['product'] = content.get('logsource', {}).get('product', '')
                rule['category'] = content.get('logsource', {}).get('category', '')
                rule['service'] = content.get('logsource', {}).get('service', '')
                rule['techniques'] = []
                rule['software'] = []
                rule['groups'] = []
                rule['tactics'] = []
                for tag in rule['tags']:
                    if tag.startswith('attack'):
                        if tag.startswith('attack.t'):
                            rule['techniques'].append(tag.replace('attack.', ''))
                        elif tag.startswith('attack.s'):
                            rule['software'].append(tag.replace('attack.', ''))
                        elif tag.startswith('attack.g'):
                            rule['groups'].append(tag.replace('attack.', ''))
                        else:
                            rule['tactics'].append(tag.replace('attack.', ''))

                rule['description'] = content['description']
                rule['filepath'] = filepath
                rules[rule_id] = rule
                rule_id += 1
                progress.update(task, advance=1)

    with open(os.path.join(ROOT, target_file), 'w') as fd:
        json.dump(rules, fd)
        return True


