
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: Ingress Tool Transfer 

Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network through the command and control channel or through alternate protocols such as [ftp](https://attack.mitre.org/software/S0095). Once present, adversaries may also transfer/spread tools between victim devices within a compromised environment (i.e. [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570)). 

Files can also be transferred using various [Web Service](https://attack.mitre.org/techniques/T1102)s as well as native or otherwise present tools on the victim system.(Citation: PTSecurity Cobalt Dec 2016)

On Windows, adversaries may use various utilities to download tools, such as `copy`, `finger`, and [PowerShell](https://attack.mitre.org/techniques/T1059/001) commands such as <code>IEX(New-Object Net.WebClient).downloadString()</code> and <code>Invoke-WebRequest</code>. On Linux and macOS systems, a variety of utilities also exist, such as `curl`, `scp`, `sftp`, `tftp`, `rsync`, `finger`, and `wget`.(Citation: t1105_lolbas)

# MITRE
## Tactic
  - command-and-control


## technique
  - T1105


# Test : MAZE Propagation Script
## OS
  - windows


## Description:
This test simulates MAZE ransomware's propogation script that searches through a list of computers, tests connectivity to them, and copies a binary file to the Windows\Temp directory of each one. 
Upon successful execution, a specified binary file will attempt to be copied to each online machine, a list of the online machines, as well as a list of offline machines will be output to a specified location.
Reference: https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html 


## Executor
powershell

# Sigma Rule
 - proc_creation_win_susp_copy_lateral_movement.yml (id: 855bc8b5-2ae8-402e-a9ed-b889e6df1900)

 - proc_creation_win_susp_copy_system32.yml (id: fff9d2b7-e11c-4a69-93d3-40ef66189767)

 - file_event_win_susp_dropper.yml (id: 297afac9-5d02-4138-8c58-b977bac60556)

 - proc_creation_win_wmic_process_creation.yml (id: 526be59f-a573-4eea-b5f7-f0973207634d)

 - proc_creation_win_susp_powershell_sub_processes.yml (id: e4b6d2a7-d8a4-4f19-acbd-943c16d90647)



[back](../index.md)
