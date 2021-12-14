# sigma_redcanaryco
Knowing which rule should sound according to the redcannary test

## Yaml file
```yaml
guid: redcanary test guid
name: Name of the test
tactic:
  - list of tactic
technique:
  - list of technique
sigma: true or false if a one rule must trigger
sigma_rule:
    - id: id of the sigma rule
      name: name of the sigma rule
    - id: can be x rules
      name: can be x rules
os:
  - list of os for the test
```

## Works in progress

- [X] better MITRE extract
- [ ] add github action
- [ ] update readme
- [ ] fix `expected <block end>, but found '<scalar>'`