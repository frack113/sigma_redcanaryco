
[back](../index.md)

Find sigma rule :x: 

# Attack: Command and Scripting Interpreter: Bash 

Adversaries may abuse Unix shell commands and scripts for execution. Unix shells are the primary command prompt on Linux and macOS systems, though many variations of the Unix shell exist (e.g. sh, bash, zsh, etc.) depending on the specific OS or distribution.(Citation: DieNet Bash)(Citation: Apple ZShell) Unix shells can control every aspect of a system, with certain commands requiring elevated privileges.

Unix shells also support scripts that enable sequential execution of commands as well as other typical programming operations such as conditionals and loops. Common uses of shell scripts include long or repetitive tasks, or the need to run the same set of commands on multiple systems.

Adversaries may abuse Unix shells to execute various commands or payloads. Interactive shells may be accessed through command and control channels or during lateral movement such as with [SSH](https://attack.mitre.org/techniques/T1021/004). Adversaries may also leverage shell scripts to deliver and execute multiple commands on victims or as part of payloads used for persistence.

# MITRE
## Tactic
  - execution


## technique
  - T1059.004


# Test : Change login shell
## OS
  - linux


## Description:
An adversary may want to use a different login shell. The chsh command changes the user login shell. The following test, creates an art user with a /bin/bash shell, changes the users shell to sh, then deletes the art user. 


## Executor
bash

# Sigma Rule


[back](../index.md)
