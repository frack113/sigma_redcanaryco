[back](../index.md)

Cover by sigma :x: 

# Attack: Archive via Utility

 An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party utilities. Many utilities exist that can archive data, including 7-Zip(Citation: 7zip Homepage), WinRAR(Citation: WinRAR Homepage), and WinZip(Citation: WinZip Homepage). Most utilities include functionality to encrypt and/or compress data.

Some 3rd party utilities may be preinstalled, such as `tar` on Linux and macOS or `zip` on Windows systems.

# MITRE
## Tactic
  - collection

## technique
  - T1560.001

# Test : Compress Data for Exfiltration With Rar

OS: ['windows']

Description: An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration.
When the test completes you should find the txt files from the %USERPROFILE% directory compressed in a file called T1560.001-data.rar in the %USERPROFILE% directory 


# Sigma

 So many other things to do...