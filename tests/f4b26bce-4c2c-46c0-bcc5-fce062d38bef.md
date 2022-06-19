
[back](../index.md)

Find sigma rule :x: 

# Attack: System Service Discovery 

Adversaries may try to gather information about registered local system services. Adversaries may obtain information about services using tools as well as OS utility commands such as <code>sc query</code>, <code>tasklist /svc</code>, <code>systemctl --type=service</code>, and <code>net start</code>.

Adversaries may use the information from [System Service Discovery](https://attack.mitre.org/techniques/T1007) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

# MITRE
## Tactic
  - discovery


## technique
  - T1007


# Test : System Service Discovery - systemctl
## OS
  - linux


## Description:
Enumerates system service using systemctl


## Executor
bash

# Sigma Rule


[back](../index.md)
