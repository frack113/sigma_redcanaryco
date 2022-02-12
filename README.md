# sigma_redcanaryco
Knowing which rule should sound according to the redcannary test

https://frack113.github.io/sigma_redcanaryco/


All information data comes from the Atomic Red Team yaml.

[Atomic Red Team Yaml Spec](https://github.com/redcanaryco/atomic-red-team/blob/master/atomic_red_team/spec.yaml)

## My Yaml file
```yaml
Attack_name: The master technique name
Attack_description: The master technique description
tactic:
  - list of tactic
technique:
  - list of technique
name: Name of the test
guid: redcanary test guid
os:
  - list of os for the test
executor: name of the executor ()
sigma: true or false if a one rule must trigger
sigma_rule:
    - id: id of the sigma rule
      name: name of the sigma rule
    - id: can be x rules
      name: can be x rules
```
