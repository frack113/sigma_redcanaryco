# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Project: redcannary_id.py
Date: 2021/12/11
Author: frack113
Version: 1.0
Description: 
    generate file for redcannary index.yaml
Requirements:
    python :)
"""

import pathlib
from ruamel.yaml import YAML
import csv

class mydata():
    def __init__(self):
        self.data = {
            'Attack_name':          "",
            'Attack_description':   "",
            'guid':                 "",
            'name':                 "",
            'tactic':               [],
            'technique':            [],
            'os':                   "",
            'description':          "",
            'sigma':                False,
            'sigma_rule':           []
        }

    def clean(self):
        self.data = {
            'Attack_name':          "",
            'Attack_description':   "",
            'guid':                 "",
            'name':                 "",
            'tactic':               [],
            'technique':            [],
            'os':                   "",
            'description':          "",
            'sigma':                False,
            'sigma_rule':           []
        }

    def add(self,head_info,test):
        self.data['Attack_name'] =  head_info['name']
        self.data['Attack_description'] =  head_info['description']
        self.data['guid'] = test['auto_generated_guid']
        self.data['name'] = test['name']
        self.data['os'] = test['supported_platforms']
        self.data['description'] = test['description']
        for tactic in head_info['tactic']:  # better way to do?
            if not tactic in self.data['tactic']:
                self.data['tactic'].append(tactic)
        for technique in head_info['technique']:
            if not technique in self.data['technique']:
                self.data['technique'].append(technique)

    def load(self,filepath):
        with filepath.open('r',encoding='UTF-8') as file:
            self.data = yaml.load(file)

    def save(self,filepath):
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with filepath.open('w',encoding='UTF-8', newline='\n') as file:
            yaml.dump(self.data,file)
    
    def build_md(self,filepath):
        my_str =   "[back](../index.md)\n"
        if self.data['sigma'] == True:
            my_str += "\nCover by sigma :heavy_check_mark: \n"
        else:
            my_str += "\nCover by sigma :x: \n"
        my_str += f"\n# Attack: {self.data['Attack_name']}\n"
        my_str += f"\n {self.data['Attack_description']}\n"
        my_str +=  "\n# MITRE\n## Tactic\n"
        for tactic in self.data['tactic']:
            my_str += f"  - {tactic}\n"
        my_str +=  "\n## technique\n"
        for technique in self.data['technique']:
            my_str += f"  - {technique}\n"
        my_str += f"\n# Test : {self.data['name']}\n"
        my_str += f"\nOS: {self.data['os']}\n"    
        my_str += f"\nDescription: {self.data['description']}\n"
        my_str +=  "\n# Sigma\n"
        for sigma in self.data['sigma_rule']:
            my_str += f" - {sigma['name']} id: {sigma['id']}\n\n"
        my_str += "\n So many other things to do..."
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with filepath.open('w',encoding='UTF-8', newline='\n') as file:
            file.write(my_str)

yaml = YAML()
yaml.preserve_quotes = True
yaml.explicit_start = False
yaml.preserve_quotes =True
yaml.width = 2000
yaml.indent(sequence=4, offset=2)

redcannary_info = mydata()

#https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/Indexes/index.yaml
# No auto update ? well next time

all_csv =[["tactic","technique","os","name","guid","sigma"]]

str_index ="""# Welcome to my beta projet
## Purpose
Knowing which rule should trigger when running a [redcannary test](https://github.com/redcanaryco/atomic-red-team)

## Tests\n
"""

with pathlib.Path('index.yaml').open('r',encoding='UTF-8') as file:
    yml_index = yaml.load(file)
    for tactic in yml_index.keys():
        for technique in yml_index[tactic]:
            atomic_tests = yml_index[tactic][technique]['atomic_tests']
            nb_tests = len(atomic_tests)
            print (f'found {tactic} / {technique} : {nb_tests} tests')
            if 'technique' in yml_index[tactic][technique]:
                head_info = {}
                technique_part =yml_index[tactic][technique]['technique']
                head_info['description'] = technique_part['description']
                head_info['name'] = technique_part['name']
                head_info['technique'] = []
                for ext_ref in technique_part['external_references']:
                    if ext_ref['source_name'] == 'mitre-attack':
                        head_info['technique'].append(ext_ref['external_id'])
                head_info['tactic'] = []
                for kill_ref in technique_part['kill_chain_phases']:
                    if kill_ref['kill_chain_name'] == 'mitre-attack':
                        head_info['tactic'].append(kill_ref['phase_name'])
            else:
                head_info ={
                    'description': "",
                    'name': "",
                    'technique': [],
                    'tactic': []
                }
            if nb_tests>0:
                for test in atomic_tests:
                    redcannary_info.clean()
                    guid = test['auto_generated_guid']
                    yml_file = pathlib.Path(f'yml/{guid}.yml')
                    if yml_file.exists():
                         redcannary_info.load(yml_file)
                    redcannary_info.add(head_info,test)
                    redcannary_info.save(yml_file)
                    md_file = pathlib.Path(f'md/tests/{guid}.md')
                    redcannary_info.build_md(md_file)
                    if redcannary_info.data['sigma'] == True:
                        smiley = " :heavy_check_mark: "
                    else:
                        smiley = " :x: "
                    all_csv.append([tactic,technique,redcannary_info.data['os'],redcannary_info.data['name'],redcannary_info.data['guid'],redcannary_info.data['sigma']])
                    str_index += f"[{redcannary_info.data['name']}](tests/{guid}.md) {redcannary_info.data['os']}{smiley}\n\n"

md_file = pathlib.Path(f'md/index.md')
with md_file.open('w',encoding='UTF-8', newline='\n') as file_id:
    file_id.write(str_index)

csv_file = pathlib.Path(f'Full_tests.csv')
with csv_file.open('w',encoding='UTF-8', newline='\n') as csvfile:
    writer = csv.writer(csvfile, delimiter=';', quoting=csv.QUOTE_MINIMAL)
    writer.writerows(all_csv)