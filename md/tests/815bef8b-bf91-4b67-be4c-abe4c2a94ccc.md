
[back](../index.md)

Find sigma rule :x: 

# Attack: Ingress Tool Transfer 

Adversaries may transfer tools or other files from an external system into a compromised environment. Files may be copied from an external adversary controlled system through the command and control channel to bring tools into the victim network or through alternate protocols with another tool such as FTP. Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp.

# MITRE
## Tactic
  - command-and-control


## technique
  - T1105


# Test : Download a File with Windows Defender MpCmdRun.exe
## OS
  - windows


## Description:
Uses the Windows Defender to download a file from the internet (must have version 4.18.2007.8-0, 4.18.2007.9, or 4.18.2009.9 installed).
The input arguments "remote_file" and "local_path" can be used to specify the download URL and the name of the output file.
By default, the test downloads the Atomic Red Team license file to the temp directory.

More info and how to find your version can be found here https://lolbas-project.github.io/lolbas/Binaries/MpCmdRun/


# Sigma Rule


[back](../index.md)
