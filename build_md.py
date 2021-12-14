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
    generate the md file
Requirements:
    python :)
"""

import pathlib
from ruamel.yaml import YAML
from  mydata import my_data

yaml = YAML()
yaml.preserve_quotes = True
yaml.explicit_start = False
yaml.preserve_quotes =True
yaml.width = 200
yaml.indent(sequence=4, offset=2)

redcannary_info = my_data(yaml)
index = {}
yml_files = pathlib.Path('./yml').glob('**/*.yml')
for yml_file in yml_files:
    print (f"Parse :{yml_file.name}")
    redcannary_info.load(yml_file)
    guid = redcannary_info.data['guid']
    md_file = pathlib.Path(f'./md/tests/{guid}.md')
    redcannary_info.build_md(md_file)
    index[guid]={'os':redcannary_info.data['os'],'name':redcannary_info.data['name']}

print("Build index")
str_index ="""# Welcome to my sigma redcannary cover projet
## Purpose
Knowing which rule should trigger when running a [redcannary test](https://github.com/redcanaryco/atomic-red-team)
When run a test many noisy can trigger too... 

## Tests\n\n
"""
for test in index.keys():
    str_index += f"[{index[test]['name']}](tests/{test}.md) {index[test]['os']}\n\n"

md_file = pathlib.Path(f'md/index.md')
with md_file.open('w',encoding='UTF-8', newline='\n') as file_id:
    file_id.write(str_index)