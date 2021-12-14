
class my_data():
    def __init__(self,yaml):
        self.yaml = yaml
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
            self.data = self.yaml.load(file)

    def save(self,filepath):
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with filepath.open('w',encoding='UTF-8', newline='\n') as file:
            self.yaml.dump(self.data,file)
    
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
        my_str += f"\nDescription:\n\n {self.data['description']}\n"
        my_str +=  "\n# Sigma\n"
        for sigma in self.data['sigma_rule']:
            my_str += f" - {sigma['name']} id: {sigma['id']}\n\n"
        my_str += "\n So many other things to do..."
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with filepath.open('w',encoding='UTF-8', newline='\n') as file:
            file.write(my_str)