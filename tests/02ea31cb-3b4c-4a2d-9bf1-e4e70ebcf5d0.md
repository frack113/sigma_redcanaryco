
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: Archive via Utility 

Adversaries may use utilities to compress and/or encrypt collected data prior to exfiltration. Many utilities include functionalities to compress, encrypt, or otherwise package data into a format that is easier/more secure to transport.

Adversaries may abuse various utilities to compress or encrypt data before exfiltration. Some third party utilities may be preinstalled, such as <code>tar</code> on Linux and macOS or <code>zip</code> on Windows systems. On Windows, <code>diantz</code> or <code> makecab</code> may be used to package collected files into a cabinet (.cab) file. <code>diantz</code> may also be used to download and compress files from remote locations (i.e. [Remote Data Staging](https://attack.mitre.org/techniques/T1074/002)).(Citation: diantz.exe_lolbas) Additionally, <code>xcopy</code> on Windows can copy files and directories with a variety of options.

Adversaries may use also third party utilities, such as 7-Zip, WinRAR, and WinZip, to perform similar activities.(Citation: 7zip Homepage)(Citation: WinRAR Homepage)(Citation: WinZip Homepage)

# MITRE
## Tactic
  - collection


## technique
  - T1560.001


# Test : Compress Data for Exfiltration With Rar
## OS
  - windows


## Description:
An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration.
When the test completes you should find the txt files from the %USERPROFILE% directory compressed in a file called T1560.001-data.rar in the %USERPROFILE% directory 


## Executor
command_prompt

# Sigma Rule
 - proc_creation_win_data_compressed_with_rar.yml (id: 6f3e2987-db24-4c78-a860-b4f4095a7095)



[back](../index.md)
