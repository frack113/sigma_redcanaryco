
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: Local Account 

Adversaries may attempt to get a listing of local system accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior.

Commands such as <code>net user</code> and <code>net localgroup</code> of the [Net](https://attack.mitre.org/software/S0039) utility and <code>id</code> and <code>groups</code>on macOS and Linux can list local users and groups. On Linux, local users can also be enumerated through the use of the <code>/etc/passwd</code> file. On macOS the <code>dscl . list /Users</code> command can be used to enumerate local accounts.

# MITRE
## Tactic
  - discovery


## technique
  - T1087.001


# Test : Enumerate all accounts on Windows (Local)
## OS
  - windows


## Description:
Enumerate all accounts
Upon execution, multiple enumeration commands will be run and their output displayed in the PowerShell session


## Executor
command_prompt

# Sigma Rule
 - proc_creation_win_susp_net_execution.yml (id: 183e7ea8-ac4b-4c23-9aec-b3dac4e401ac)

 - proc_creation_win_cmdkey_recon.yml (id: 07f8bdc2-c9b3-472a-9817-5a670b872f53)



[back](../index.md)
