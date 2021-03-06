
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: Scheduled Task 

Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The <code>schtasks</code> can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel. In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library to create a scheduled task.

The deprecated [at](https://attack.mitre.org/software/S0110) utility could also be abused by adversaries (ex: [At (Windows)](https://attack.mitre.org/techniques/T1053/002)), though <code>at.exe</code> can not access tasks created with <code>schtasks</code> or the Control Panel.

An adversary may use Windows Task Scheduler to execute programs at system startup or on a scheduled basis for persistence. The Windows Task Scheduler can also be abused to conduct remote Execution as part of Lateral Movement and or to run a process under the context of a specified account (such as SYSTEM).

# MITRE
## Tactic
  - privilege-escalation
  - persistence
  - execution


## technique
  - T1053.005


# Test : Powershell Cmdlet Scheduled Task
## OS
  - windows


## Description:
Create an atomic scheduled task that leverages native powershell cmdlets.

Upon successful execution, powershell.exe will create a scheduled task to spawn cmd.exe at 20:10.


## Executor
powershell

# Sigma Rule
 - posh_ps_cmdlet_scheduled_task.yml (id: 363eccc0-279a-4ccf-a3ab-24c2e63b11fb)



[back](../index.md)
