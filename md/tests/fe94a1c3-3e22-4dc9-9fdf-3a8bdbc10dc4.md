
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: Application Window Discovery 

Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used or give context to information collected by a keylogger.

# MITRE
## Tactic
  - discovery


## technique
  - T1010


# Test : List Process Main Windows - C# .NET
## OS
  - windows


## Description:
Compiles and executes C# code to list main window titles associated with each process.

Upon successful execution, powershell will download the .cs from the Atomic Red Team repo, and cmd.exe will compile and execute T1010.exe. Upon T1010.exe execution, expected output will be via stdout.


# Sigma Rule
 - win_susp_csc_folder.yml (id: dcaa3f04-70c3-427a-80b4-b870d73c94c4)



[back](../index.md)
