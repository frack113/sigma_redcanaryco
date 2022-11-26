
[back](../index.md)

Find sigma rule :x: 

# Attack: Active Setup 

Adversaries may achieve persistence by adding a Registry key to the Active Setup of the local machine. Active Setup is a Windows mechanism that is used to execute programs when a user logs in. The value stored in the Registry key will be executed after a user logs into the computer.(Citation: Klein Active Setup 2010) These programs will be executed under the context of the user and will have the account's associated permissions level.

Adversaries may abuse Active Setup by creating a key under <code> HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\</code> and setting a malicious value for <code>StubPath</code>. This value will serve as the program that will be executed when a user logs into the computer.(Citation: Mandiant Glyer APT 2010)(Citation: Citizenlab Packrat 2015)(Citation: FireEye CFR Watering Hole 2012)(Citation: SECURELIST Bright Star 2015)(Citation: paloalto Tropic Trooper 2016)

Adversaries can abuse these components to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use [Masquerading](https://attack.mitre.org/techniques/T1036) to make the Registry entries look as if they are associated with legitimate programs.

# MITRE
## Tactic
  - persistence
  - privilege-escalation


## technique
  - T1547.014


# Test : HKLM - Add malicious StubPath value to existing Active Setup Entry
## OS
  - windows


## Description:
This test will add a StubPath entry to the Active Setup native registry key associated with 'Internet Explorer Core Fonts' (UUID {C9E9A340-D1F1-11D0-821E-444553540600}) 
Said key doesn't have a StubPath value by default, by adding one it will launch calc by forcing to run active setup using runonce.exe /AlternateShellStartup. 
Without the last command it will normally run on next user logon. Note: this test will only run once successfully if no cleanup command is run in between test.


## Executor
powershell

# Sigma Rule


[back](../index.md)
