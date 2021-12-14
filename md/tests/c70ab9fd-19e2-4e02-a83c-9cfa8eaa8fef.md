[back](../index.md)

Cover by sigma :heavy_check_mark: 

# Attack: Domain Account

 Adversaries may attempt to get a listing of domain accounts. This information can help adversaries determine which domain accounts exist to aid in follow-on behavior.

Commands such as <code>net user /domain</code> and <code>net group /domain</code> of the [Net](https://attack.mitre.org/software/S0039) utility, <code>dscacheutil -q group</code>on macOS, and <code>ldapsearch</code> on Linux can list domain users and groups.

# MITRE
## Tactic
  - discovery

## technique
  - T1087.002

# Test : Enumerate Default Domain Admin Details (Domain)

OS: ['windows']

Description: This test will enumerate the details of the built-in domain admin account


# Sigma
 - win_susp_net_execution.yml id: 183e7ea8-ac4b-4c23-9aec-b3dac4e401ac


 So many other things to do...