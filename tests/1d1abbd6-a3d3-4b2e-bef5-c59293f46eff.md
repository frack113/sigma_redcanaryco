
[back](../index.md)
Find sigma rule :x: 

# Attack: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol 

Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. 

Adversaries may opt to obfuscate this data, without the use of encryption, within network protocols that are natively unencrypted (such as HTTP, FTP, or DNS). This may include custom or publicly available encoding/compression algorithms (such as base64) as well as embedding data within protocol headers and fields. 

# MITRE
## Tactic
  - exfiltration


## technique
  - T1048.003


# Test : Exfiltration Over Alternative Protocol - HTTP
## OS
  - macos
  - linux


## Description:
A firewall rule (iptables or firewalld) will be needed to allow exfiltration on port 1337.

Upon successful execution, sh will be used to make a directory (/tmp/victim-staging-area), write a txt file, and host the directory with Python on port 1337, to be later downloaded.


# Sigma Rule


[back](../index.md)
