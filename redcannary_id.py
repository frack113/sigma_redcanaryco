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

class mydata():
    def __init__(self):
        self.data = {
            'guid':         "",
            'name':         "",
            'tactic':       [],
            'technique':    [],
            'sigma':        False,
            'sigma_rule':   []
        }

    def clean(self):
        self.data = {
            'guid':         "",
            'name':         "",
            'tactic':       [],
            'technique':    [],
            'sigma':        False,
            'sigma_rule':   []
        }
    def add(self,tactic,technique,test):
        self.data['guid'] = test['auto_generated_guid']
        self.data['name'] = test['name']
        if not tactic in self.data['tactic']:
            self.data['tactic'].append(tactic)
        if not technique in self.data['technique']:
            self.data['technique'].append(technique)   
    
    def load(self,filepath):
        with filepath.open('r',encoding='UTF-8') as file:
            self.data = yaml.load(file)
    
    def build_md(self):
        my_str =   "[back](../index.md)\n"
        my_str += f"# {self.data['name']}\n"
        if self.data['sigma'] == True:
            my_str += f"Cover by sigma :heavy_check_mark: \n"
        else:
            my_str += f"Cover by sigma :x: \n"
        my_str +=  "\n## MITRE\n### Tactic\n"
        for tactic in self.data['tactic']:
            my_str += f"  - {tactic}\n"
        my_str +=  "\n### technique\n"
        for technique in self.data['technique']:
            my_str += f"  - {technique}\n"
        my_str +=  "\n### Sigma\n"
        for sigma in self.data['sigma_rule']:
            my_str += f" - {sigma['name']} id: {sigma['id']}\n\n"
        my_str += "\n So many other things to do..."
        return my_str

yaml = YAML()
yaml.preserve_quotes = True
yaml.explicit_start = False
yaml.preserve_quotes =True
yaml.width = 2000
yaml.indent(sequence=4, offset=2)

redcannary_info = mydata()

#https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/Indexes/index.yaml
# No auto update ? well next time
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
            if nb_tests>0:
                for test in atomic_tests:
                    redcannary_info.clean()
                    guid = test['auto_generated_guid']
                    yml_file = pathlib.Path(f'yml/{guid}.yml')
                    if yml_file.exists():
                         redcannary_info.load(yml_file)
                    redcannary_info.add(tactic,technique,test)
                    yml_file.parent.mkdir(parents=True, exist_ok=True)
                    with yml_file.open('w',encoding='UTF-8', newline='\n') as file_id:
                        yaml.dump(redcannary_info.data,file_id)
                    md_file = pathlib.Path(f'md/tests/{guid}.md')
                    md_file.parent.mkdir(parents=True, exist_ok=True)
                    with md_file.open('w',encoding='UTF-8', newline='\n') as file_id:
                        file_id.write(redcannary_info.build_md())
                    if redcannary_info.data['sigma'] == True:
                        smiley = " :heavy_check_mark: "
                    else:
                        smiley = " :x: "
                    str_index += f"[{redcannary_info.data['name']}](tests/{guid}.md){smiley}\n\n"

md_file = pathlib.Path(f'md/index.md')
with md_file.open('w',encoding='UTF-8', newline='\n') as file_id:
    file_id.write(str_index)