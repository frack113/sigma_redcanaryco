
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: Permission Groups Discovery: Domain Groups 

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
 - posh_pm_susp_ad_group_reco.yml (id: 815bfc17-7fc6-4908-a55e-2f37b98cedb4)

 - proc_creation_win_non_interactive_powershell.yml (id: f4bbd493-b796-416e-bbf2-121235348529)

 - posh_ps_susp_get_adgroup.yml (id: 8c3a6607-b7dc-4f0d-a646-ef38c00b76ee)

 - net_connection_win_powershell_network_connection.yml (id: 1f21ec3f-810d-4b0e-8045-322202e22b4b)



[back](../index.md)
