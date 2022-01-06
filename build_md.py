# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Project: redcannary_id.py
Date: 2021/12/27
Author: frack113
Version: 1.3
Description: 
    generate the md file
Requirements:
    python :)
"""

import pathlib
from ruamel.yaml import YAML
from mydata import my_data

yaml = YAML()
yaml.preserve_quotes = True
yaml.explicit_start = False
yaml.width = 200
yaml.indent(sequence=4, offset=2)

redcannary_info = my_data(yaml)
index = {}
yml_files = pathlib.Path("./yml").glob("**/*.yml")
for yml_file in yml_files:
    print(f"Parse :{yml_file.name}")

    redcannary_info.load(yml_file)

    guid = redcannary_info.data["guid"]
    md_file = pathlib.Path(f"./md/tests/{guid}.md")
    redcannary_info.build_md(md_file)
    index[guid] = {
        "os": redcannary_info.data["os"],
        "name": redcannary_info.data["name"],
        "technique": redcannary_info.data["technique"][0],
        "file_link": f"tests/{guid}.md",
        "sigma": redcannary_info.data["sigma"],
        "rule": redcannary_info.data["sigma_rule"],
    }

print("Build index")

full_technique = {}
full_sigma ={}
for dictionnary in index.values():
    if dictionnary["technique"] in full_technique:
        full_technique[dictionnary["technique"]].append(dictionnary)

    else:
        full_technique[dictionnary["technique"]] = [dictionnary]
    if dictionnary['sigma'] :
        for rule in dictionnary['rule']:
            local_dico = {
                    "technique": dictionnary["technique"],
                    "name": dictionnary["name"],
                    "file_link": dictionnary["file_link"],
                }
            if rule['name'] in full_sigma:
                full_sigma[rule['name']].append(local_dico)
            else:
                full_sigma[rule['name']] = [local_dico,]

string_index = """# Welcome to my sigma redcannary cover project

## Purpose

Knowing which rule should trigger when running a [redcannary test](https://github.com/redcanaryco/atomic-red-team)

Caution: a test can generate a lot of noise...

<p align="center" width="100%">
    <img width="50%" src="./png/allright.jpg"> 
</p>

[hidden index ;)](./index2.md)

## Tests\n\n
"""

for technique, test_lst in full_technique.items():
    string_index += f"\n### {technique}\n"
    for test in test_lst:
        state = ":heavy_check_mark:" if test["sigma"] == True else ":x:"
        string_index += f"[{test['name']}]({test['file_link']}) {test['os']} (sigma rule {state})\n\n"

md_file = pathlib.Path(f"md/index.md")
with md_file.open("w", encoding="UTF-8", newline="\n") as file_id:
    file_id.write(string_index)

print("Build index2")
string_index = """# Find a test to trigger a SigmaHQ rule

[back](./index.md)

## The rules\n
"""
namekeys = [x for x in full_sigma.keys()]
namekeys.sort()
for name in namekeys:
    string_index +=  f"\n* {name}"
    for link in full_sigma[name]:
        string_index +=  f"\n  * {link['technique']} [{link['name']}]({link['file_link']})"
 
md_file = pathlib.Path(f"md/index2.md")
with md_file.open("w", encoding="UTF-8", newline="\n") as file_id:
    file_id.write(string_index)