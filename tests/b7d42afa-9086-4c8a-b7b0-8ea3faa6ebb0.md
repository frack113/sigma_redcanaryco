
[back](../index.md)

Find sigma rule :x: 

# Attack: Cron 

Adversaries may abuse the <code>cron</code> utility to perform task scheduling for initial or recurring execution of malicious code.(Citation: 20 macOS Common Tools and Techniques) The <code>cron</code> utility is a time-based job scheduler for Unix-like operating systems.  The <code> crontab</code> file contains the schedule of cron entries to be run and the specified times for execution. Any <code>crontab</code> files are stored in operating system-specific file paths.

An adversary may use <code>cron</code> in Linux or Unix environments to execute programs at system startup or on a scheduled basis for [Persistence](https://attack.mitre.org/tactics/TA0003). 

# MITRE
## Tactic
  - privilege-escalation
  - persistence
  - execution


## technique
  - T1053.003


# Test : Cron - Add script to all cron subfolders
## OS
  - macos
  - linux


## Description:
This test adds a script to /etc/cron.hourly, /etc/cron.daily, /etc/cron.monthly and /etc/cron.weekly folders configured to execute on a schedule. This technique was used by the threat actor Rocke during the exploitation of Linux web servers.


## Executor
bash

# Sigma Rule


[back](../index.md)
