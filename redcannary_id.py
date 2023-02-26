# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Project: redcannary_id.py
Date: 2022/01/27
Author: frack113
Version: 1.4.2
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
import re

from dataclasses import dataclass

yaml = YAML()
yaml.preserve_quotes = True
yaml.explicit_start = False
yaml.width = 200
yaml.indent(sequence=4, offset=2)

redcannary_info = my_data(yaml)


@dataclass
class sigma:
    uuid = {}
    name = {}
    url = {}
    tag = {}
    use = {}

@dataclass
class csvdata:
    header = [
        "tactic",
        "technique",
        "executor",
        "os",
        "name",
        "guid",
        "sigma",
        "nmr_test",
    ]
    data = [header]


def load_sigma_yaml(path) -> sigma:
    sigma_data = sigma()
    sigmahq_files = pathlib.Path(path).glob("**/*.yml")

    for sigmahq_yml in sigmahq_files:
        with sigmahq_yml.open("r", encoding="UTF-8") as file:
            yml_sigma = yaml.load(file)
            sigma_data.uuid[yml_sigma["id"]] = sigmahq_yml.name
            sigma_data.name[sigmahq_yml.name] = yml_sigma["id"]
            sigma_data.url[sigmahq_yml.name] = str(
                pathlib.PurePosixPath(sigmahq_yml)
            ).replace("../sigma", "https://github.com/SigmaHQ/sigma/tree/master")

            if "tags" in yml_sigma:
                for tag in yml_sigma["tags"]:
                    if re.match("attack.t\d+.*", tag):
                        mitre = tag.replace("attack.t", "T")

                        if not mitre in sigma_data.tag:
                            sigma_data.tag[mitre] = []

                        sigma_data.tag[mitre].append(sigmahq_yml.name)

    sigma_data.use = {name: False for name in sigma_data.name.keys()}

    return sigma_data


def check_redcanary_yaml(path, delta):
    need_to_download = False

    if pathlib.Path(path).exists():
        epoch_now = time.time()
        file_lstat = pathlib.Path(path).lstat()
        delta_time = epoch_now - file_lstat.st_mtime

        if delta_time > delta:
            need_to_download = True
            pathlib.Path(path).unlink()

    else:
        need_to_download = True

    if need_to_download:

        my_file = requests.get(
            "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/Indexes/index.yaml"
        )

        with pathlib.Path(path).open("w", encoding="UTF-8", newline="\n") as file:
            file.write(my_file.content.decode())


sigma_data = load_sigma_yaml("../sigma/rules")
check_redcanary_yaml("index.yaml", 86400)

full_csv = csvdata()


test_csv = []
warning_log = []
valid_guid = []

with pathlib.Path("index.yaml").open("r", encoding="UTF-8") as file:
    print("Load index.yaml...")
    yml_index = yaml.load(file)

    for tactic in yml_index.keys():
        for technique in yml_index[tactic]:
            atomic_tests = yml_index[tactic][technique]["atomic_tests"]
            nb_tests = len(atomic_tests)

            print(f"Found {tactic} / {technique} : {nb_tests} tests")

            head_info = {
                "description": "",
                "name": "",
                "technique": [],
                "tactic": [],
            }

            if "technique" in yml_index[tactic][technique]:

                head_info["description"] = yml_index[tactic][technique]["technique"][
                    "description"
                ]
                head_info["name"] = yml_index[tactic][technique]["technique"]["name"]

                for ext_ref in yml_index[tactic][technique]["technique"][
                    "external_references"
                ]:
                    if ext_ref["source_name"] == "mitre-attack":
                        head_info["technique"].append(ext_ref["external_id"])

                for kill_ref in yml_index[tactic][technique]["technique"][
                    "kill_chain_phases"
                ]:
                    if kill_ref["kill_chain_name"] == "mitre-attack":
                        head_info["tactic"].append(kill_ref["phase_name"])

            if nb_tests > 0:
                nmr_test = 0

                for test in atomic_tests:
                    nmr_test += 1

                    redcannary_info.clean()

                    guid = test["auto_generated_guid"]
                    valid_guid.append(guid)
                    yml_file = pathlib.Path(f"yml/{guid}.yml")

                    if yml_file.exists():
                        redcannary_info.load(yml_file)

                    redcannary_info.add(head_info, test)

                    if len(redcannary_info.data["sigma_rule"]) > 0:
                        for rule in redcannary_info.data["sigma_rule"]:
                            if rule["id"] in sigma_data.uuid:
                                rule["name"] = sigma_data.uuid[rule["id"]]
                                sigma_data.use[rule["name"]] = True

                            else:
                                if rule["name"] in sigma_data.name:
                                    rule["id"] = sigma_data.name[rule["name"]]
                                    sigma_data.use[rule["name"]] = True

                                    
                                else:
                                    warning_log.append(
                                        f'No fix found in {guid} file for Unidentified sigma id : {rule["id"]} / {rule["name"]}'
                                    )

                    redcannary_info.order()
                    redcannary_info.save(yml_file)

                    full_csv.data.append(
                        [
                            tactic,
                            technique,
                            redcannary_info.data["executor"],
                            redcannary_info.data["os"],
                            redcannary_info.data["name"],
                            redcannary_info.data["guid"],
                            redcannary_info.data["sigma"],
                            nmr_test,
                        ]
                    )

            else:
                if technique in sigma_data.tag:
                    print(
                        f"Found {len(sigma_data.tag[technique])} sigma rule(s)"
                    )
                    info = [
                        tactic,
                        technique,
                        ",".join(sigma_data.tag[technique]),
                    ]
                    test_csv.append(info)

csv_file = pathlib.Path("Full_tests.csv")
with csv_file.open("w", encoding="UTF-8", newline="\n") as csvfile:
    writer = csv.writer(csvfile, delimiter=";", quoting=csv.QUOTE_MINIMAL)
    writer.writerows(full_csv.data)

if len(test_csv) > 0:
    csv_file = pathlib.Path("missing_tests.csv")

    with csv_file.open("w", encoding="UTF-8", newline="\n") as csvfile:
        writer = csv.writer(csvfile, delimiter=";", quoting=csv.QUOTE_MINIMAL)
        writer.writerows(test_csv)

if len(warning_log) > 0:
    print("--------- Warning Found ---------")

    for warn_srt in warning_log:
        print(warn_srt)

print("--------- Check remove Test ---------")
guid_files = pathlib.Path("yml/").glob("**/*.yml")

for guid_file in guid_files:
    if guid_file.stem not in valid_guid:
        print(f"{guid_file.name} remove")
        guid_file.unlink()

csv_file = pathlib.Path("sigma_rule.csv")
with csv_file.open("w", encoding="UTF-8", newline="\n") as csvfile:
    writer = csv.writer(csvfile, delimiter=";", quoting=csv.QUOTE_MINIMAL)
    my_row= [[key,value] for key,value in sigma_data.use.items()]
    writer.writerows(my_row)
