
[back](../index.md)

Find sigma rule :x: 

# Attack: Ingress Tool Transfer 

Adversaries may transfer tools or other files from an external system into a compromised environment. Files may be copied from an external adversary controlled system through the command and control channel to bring tools into the victim network or through alternate protocols with another tool such as FTP. Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp.

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


[back](../index.md)
