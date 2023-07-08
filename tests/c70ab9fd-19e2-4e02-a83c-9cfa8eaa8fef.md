
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: Account Discovery: Domain Account 

Adversaries may attempt to get a listing of domain accounts. This information can help adversaries determine which domain accounts exist to aid in follow-on behavior such as targeting specific accounts which possess particular privileges.

Commands such as <code>net user /domain</code> and <code>net group /domain</code> of the [Net](https://attack.mitre.org/software/S0039) utility, <code>dscacheutil -q group</code>on macOS, and <code>ldapsearch</code> on Linux can list domain users and groups. [PowerShell](https://attack.mitre.org/techniques/T1059/001) cmdlets including <code>Get-ADUser</code> and <code>Get-ADGroupMember</code> may enumerate members of Active Directory groups.  

# MITRE
## Tactic
  - discovery


## technique
  - T1087.002


# Test : Enumerate Default Domain Admin Details (Domain)
## OS
  - windows


## Description:
This test will enumerate the details of the built-in domain admin account


## Executor
command_prompt

# Sigma Rule
 - proc_creation_win_net_susp_execution.yml (id: 183e7ea8-ac4b-4c23-9aec-b3dac4e401ac)



[back](../index.md)
