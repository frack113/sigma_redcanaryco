import copy
from collections import OrderedDict


class my_data:
    def __init__(self, yaml):
        self.yaml = yaml
        self.data = {
            "Attack_name": "",
            "Attack_description": "",
            "guid": "",
            "name": "",
            "tactic": [],
            "technique": [],
            "os": "",
            "description": "",
            "executor": "",
            "sigma": False,
            "sigma_rule": [],
        }

    def clean(self):
        self.data = {
            "Attack_name": "",
            "Attack_description": "",
            "guid": "",
            "name": "",
            "tactic": [],
            "technique": [],
            "os": "",
            "description": "",
            "executor": "",
            "sigma": False,
            "sigma_rule": [],
        }

    # Use to add missing field when update class
    def check(self):
        # pass
        # file deepcode ignore UpdateAPI: <please specify a reason of ignoring this>
        if not "executor" in self.data.keys():
            self.data["executor"]= ""

    def add(self, head_info, test):
        self.data["Attack_name"] = head_info["name"]
        self.data["Attack_description"] = head_info["description"]
        self.data["guid"] = test["auto_generated_guid"]
        self.data["name"] = test["name"]
        self.data["os"] = test["supported_platforms"]
        self.data["description"] = test["description"]
        self.data["executor"] = test["executor"]["name"]
        for tactic in head_info["tactic"]:  # better way to do?
            if not tactic in self.data["tactic"]:
                self.data["tactic"].append(tactic)
        for technique in head_info["technique"]:
            if not technique in self.data["technique"]:
                self.data["technique"].append(technique)
        self.data["sigma"] = True if len(self.data["sigma_rule"])>0 else False

    def order(self):
        old_yml = copy.deepcopy(self.data)
        self.data = {}
        self.data["Attack_name"] = old_yml["Attack_name"]
        self.data["Attack_description"] = old_yml["Attack_description"]
        self.data["guid"] = old_yml["guid"]
        self.data["name"] = old_yml["name"]
        self.data["tactic"] = old_yml["tactic"]
        self.data["technique"] = old_yml["technique"]
        self.data["os"] = old_yml["os"]
        self.data["description"] = old_yml["description"]
        self.data["executor"] = old_yml["executor"]
        self.data["sigma"] = old_yml["sigma"]
        self.data["sigma_rule"] = old_yml["sigma_rule"]

    def load(self, filepath):
        with filepath.open("r", encoding="UTF-8") as file:
            self.data = self.yaml.load(file)
        self.check()

    def save(self, filepath):  # very bad because of scolar -> |2
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with filepath.open("w", encoding="UTF-8", newline="\n") as file:
            self.yaml.dump(self.data, file)
        with filepath.open("r", encoding="UTF-8", newline="\n") as file:
            file_lines = file.readlines()
        with filepath.open("w", encoding="UTF-8", newline="\n") as file:
            for line in file_lines:
                file.write(line.replace("|4", "|-").replace("|2", "|-"))

    def build_md(self, filepath):
        test_str = """
[back](../index.md)

Find sigma rule %%state%% 

# Attack: %%Attack_name%% 

%%Attack_description%%

# MITRE
## Tactic
%%tactic%%

## technique
%%technique%%

# Test : %%test_name%%
## OS
%%os%%

## Description:
%%description%%

## Executor
%%executor%%

# Sigma Rule
%%sigma_rule%%

[back](../index.md)
"""
        state = ":heavy_check_mark:" if self.data["sigma"] == True else ":x:"
        str_tactic = ""
        for tactic in self.data["tactic"]:
            str_tactic += f"  - {tactic}\n"
        str_technique = ""
        for technique in self.data["technique"]:
            str_technique += f"  - {technique}\n"
        str_os = ""
        for os in self.data["os"]:
            str_os += f"  - {os}\n"
        str_sigma = ""
        for sigma in self.data["sigma_rule"]:
            str_sigma += f" - {sigma['name']} (id: {sigma['id']})\n\n"
        test_str = test_str.replace("%%state%%", state)
        test_str = test_str.replace("%%Attack_name%%", self.data["Attack_name"])
        test_str = test_str.replace(
            "%%Attack_description%%", self.data["Attack_description"]
        )
        test_str = test_str.replace("%%tactic%%", str_tactic)
        test_str = test_str.replace("%%technique%%", str_technique)
        test_str = test_str.replace("%%test_name%%", self.data["name"])
        test_str = test_str.replace("%%os%%", str_os)
        test_str = test_str.replace("%%description%%", self.data["description"])
        test_str = test_str.replace("%%executor%%", self.data["executor"])
        test_str = test_str.replace("%%sigma_rule%%", str_sigma)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with filepath.open("w", encoding="UTF-8", newline="\n") as file:
            file.write(test_str)
