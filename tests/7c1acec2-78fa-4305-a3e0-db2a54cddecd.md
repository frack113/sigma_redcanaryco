
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: PowerShell 

Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. (Citation: TechNet PowerShell) Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the <code>Start-Process</code> cmdlet which can be used to run an executable and the <code>Invoke-Command</code> cmdlet which runs a command locally or on a remote computer (though administrator permissions are required to use PowerShell to connect to remote systems).

PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk.

A number of PowerShell-based offensive testing tools are available, including [Empire](https://attack.mitre.org/software/S0363),  [PowerSploit](https://attack.mitre.org/software/S0194), [PoshC2](https://attack.mitre.org/software/S0378), and PSAttack.(Citation: Github PSAttack)

PowerShell commands/scripts can also be executed without directly invoking the <code>powershell.exe</code> binary through interfaces to PowerShell's underlying <code>System.Management.Automation</code> assembly DLL exposed through the .NET framework and Windows Common Language Interface (CLI). (Citation: Sixdub PowerPick Jan 2016)(Citation: SilentBreak Offensive PS Dec 2015)(Citation: Microsoft PSfromCsharp APR 2014)

# MITRE
## Tactic
  - execution


## technique
  - T1059.001


# Test : PowerShell Session Creation and Use
## OS
  - windows


## Description:
Connect to a remote powershell session and interact with the host.
Upon execution, network test info and 'T1086 PowerShell Session Creation and Use' will be displayed.


# Sigma Rule
 - posh_ps_remote_session_creation.yml (id: a0edd39f-a0c6-4c17-8141-261f958e8d8f)

 - posh_ps_remove_item_path.yml (id: b8af5f36-1361-4ebe-9e76-e36128d947bf)

 - sysmon_remote_powershell_session_network.yml (id: c539afac-c12a-46ed-b1bd-5a5567c9f045)

 - win_remote_powershell_session_process.yml (id: 734f8d9b-42b8-41b2-bcf5-abaf49d5a3c8)

 - image_load_wsman_provider_image_load.yml (id: ad1f4bb9-8dfb-4765-adb6-2a7cfb6c0f94)



[back](../index.md)
