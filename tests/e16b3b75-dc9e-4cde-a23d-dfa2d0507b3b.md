
[back](../index.md)
Find sigma rule :x: 

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


# Test : WMI Invoke-CimMethod Scheduled Task
## OS
  - windows


## Description:
Create an scheduled task that executes notepad.exe after user login from XML by leveraging WMI class PS_ScheduledTask. Does the same thing as Register-ScheduledTask cmdlet behind the scenes.


# Sigma Rule


[back](../index.md)
