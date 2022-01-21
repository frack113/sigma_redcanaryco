
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: System Network Connections Discovery 

Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network. 

An adversary who gains access to a system that is part of a cloud-based environment may map out Virtual Private Clouds or Virtual Networks in order to determine what systems and services are connected. The actions performed are likely the same types of discovery techniques depending on the operating system, but the resulting information may include details about the networked cloud environment relevant to the adversary's goals. Cloud providers may have different ways in which their virtual networks operate.(Citation: Amazon AWS VPC Guide)(Citation: Microsoft Azure Virtual Network Overview)(Citation: Google VPC Overview)

Utilities and commands that acquire this information include [netstat](https://attack.mitre.org/software/S0104), "net use," and "net session" with [Net](https://attack.mitre.org/software/S0039). In Mac and Linux, [netstat](https://attack.mitre.org/software/S0104) and <code>lsof</code> can be used to list current connections. <code>who -a</code> and <code>w</code> can be used to show which users are currently logged in, similar to "net session".

# MITRE
## Tactic
  - discovery


## technique
  - T1049


# Test : System Network Connections Discovery with PowerShell
## OS
  - windows


## Description:
Get a listing of network connections.

Upon successful execution, powershell.exe will execute `get-NetTCPConnection`. Results will output via stdout.


# Sigma Rule
 - posh_pm_susp_get_nettcpconnection.yml (id: aff815cc-e400-4bf0-a47a-5d8a2407d4e1)



[back](../index.md)
