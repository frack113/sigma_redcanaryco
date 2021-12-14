# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Project: redcannary_id.py
Date: 2021/12/14
Author: frack113
Version: 1.1
Description: 
    generate file for redcannary index.yaml
Requirements:
    python :)
"""

import pathlib
from ruamel.yaml import YAML
import csv
from  mydata import my_data


yaml = YAML()
yaml.preserve_quotes = True
yaml.explicit_start = False
yaml.preserve_quotes =True
yaml.width = 200
yaml.indent(sequence=4, offset=2)

redcannary_info = my_data(yaml)

#https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/Indexes/index.yaml
# No auto update ? well next time

all_csv =[["tactic","technique","os","name","guid","sigma"]]

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
                    all_csv.append([tactic,technique,redcannary_info.data['os'],redcannary_info.data['name'],redcannary_info.data['guid'],redcannary_info.data['sigma']])

csv_file = pathlib.Path(f'Full_tests.csv')
with csv_file.open('w',encoding='UTF-8', newline='\n') as csvfile:
    writer = csv.writer(csvfile, delimiter=';', quoting=csv.QUOTE_MINIMAL)
    writer.writerows(all_csv)