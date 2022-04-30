
[back](../index.md)

Find sigma rule :x: 

# Attack: System Service Discovery 

Adversaries may try to get information about registered services. Commands that may obtain information about services using operating system utilities are "sc," "tasklist /svc" using [Tasklist](https://attack.mitre.org/software/S0057), and "net start" using [Net](https://attack.mitre.org/software/S0039), but adversaries may also use other tools as well. Adversaries may use the information from [System Service Discovery](https://attack.mitre.org/techniques/T1007) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

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
