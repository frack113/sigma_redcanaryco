
[back](../index.md)

Find sigma rule :x: 

# Attack: Domain Groups 

Adversaries may attempt to find domain-level groups and permission settings. The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as domain administrators.

Commands such as <code>net group /domain</code> of the [Net](https://attack.mitre.org/software/S0039) utility,  <code>dscacheutil -q group</code> on macOS, and <code>ldapsearch</code> on Linux can list domain-level groups.

# MITRE
## Tactic
  - discovery


## technique
  - T1069.002


# Test : Enumerate Active Directory Groups with Get-AdGroup
## OS
  - windows


## Description:
The following Atomic test will utilize Get-AdGroup to enumerate groups within Active Directory.
Upon successful execution a listing of groups will output with their paths in AD.
Reference: https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup?view=windowsserver2022-ps


## Executor
powershell

# Sigma Rule


[back](../index.md)
