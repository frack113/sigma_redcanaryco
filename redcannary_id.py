# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Project: redcannary_id.py
Date: 2022/01/09
Author: frack113
Version: 1.3
Description: 
    generate file for redcannary index.yaml
Requirements:
    python :)
"""

import pathlib
from ruamel.yaml import YAML
from mydata import my_data
import csv
import requests
from collections import OrderedDict
import time

yaml = YAML()
yaml.preserve_quotes = True
yaml.explicit_start = False
yaml.width = 200
yaml.indent(sequence=4, offset=2)

redcannary_info = my_data(yaml)

need_to_download = False

if pathlib.Path("index.yaml").exists():
    epoch_now = time.time()
    file_lstat = pathlib.Path("index.yaml").lstat()
    delta_time = epoch_now-file_lstat.st_mtime
    if  delta_time > 86400:
        need_to_download = True
        pathlib.Path("index.yaml").unlink()
        
        print (f"index.yaml is {delta_time}s old need to download")

else:
    need_to_download = True

if need_to_download:
    print("Download index.yaml")

    url = "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/Indexes/index.yaml"
    my_file = requests.get(url)

    with pathlib.Path("index.yaml").open("w", encoding="UTF-8", newline="\n") as file:
        file.write(my_file.content.decode())

all_csv = [["tactic", "technique", "os", "name", "guid", "sigma", "nmr_test"]]

with pathlib.Path("index.yaml").open("r", encoding="UTF-8") as file:
    print("Load index.yaml...")
    yml_index = yaml.load(file)

    for tactic in yml_index.keys():
        for technique in yml_index[tactic]:
            atomic_tests = yml_index[tactic][technique]["atomic_tests"]
            nb_tests = len(atomic_tests)

            print(f"found {tactic} / {technique} : {nb_tests} tests")

            if "technique" in yml_index[tactic][technique]:
                technique_part = yml_index[tactic][technique]["technique"]
                
                head_info = {}
                head_info["description"] = technique_part["description"]
                head_info["name"] = technique_part["name"]
                head_info["technique"] = []

                for ext_ref in technique_part["external_references"]:
                    if ext_ref["source_name"] == "mitre-attack":
                        head_info["technique"].append(ext_ref["external_id"])

                head_info["tactic"] = []

                for kill_ref in technique_part["kill_chain_phases"]:
                    if kill_ref["kill_chain_name"] == "mitre-attack":
                        head_info["tactic"].append(kill_ref["phase_name"])

            else:
                head_info = {
                    "description": "",
                    "name": "",
                    "technique": [],
                    "tactic": [],
                }

            if nb_tests > 0:
                nmr_test = 0

                for test in atomic_tests:
                    nmr_test += 1

                    redcannary_info.clean()

                    guid = test["auto_generated_guid"]
                    yml_file = pathlib.Path(f"yml/{guid}.yml")

                    if yml_file.exists():
                        redcannary_info.load(yml_file)

                    redcannary_info.add(head_info, test)
                    redcannary_info.order()
                    redcannary_info.save(yml_file)

                    all_csv.append(
                        [
                            tactic,
                            technique,
                            redcannary_info.data["os"],
                            redcannary_info.data["name"],
                            redcannary_info.data["guid"],
                            redcannary_info.data["sigma"],
                            nmr_test,
                        ]
                    )

csv_file = pathlib.Path("Full_tests.csv")

with csv_file.open("w", encoding="UTF-8", newline="\n") as csvfile:
    writer = csv.writer(csvfile, delimiter=";", quoting=csv.QUOTE_MINIMAL)
    writer.writerows(all_csv)
