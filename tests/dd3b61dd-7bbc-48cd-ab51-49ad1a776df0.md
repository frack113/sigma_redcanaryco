
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: Ingress Tool Transfer 

Adversaries may transfer tools or other files from an external system into a compromised environment. Files may be copied from an external adversary controlled system through the command and control channel to bring tools into the victim network or through alternate protocols with another tool such as FTP. Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp.

# MITRE
## Tactic
  - command-and-control


## technique
  - T1105


# Test : certutil download (urlcache)
## OS
  - windows


## Description:
Use certutil -urlcache argument to download a file from the web. Note - /urlcache also works!


## Executor
command_prompt

# Sigma Rule
 - file_event_win_shell_write_susp_directory.yml (id: 1277f594-a7d1-4f28-a2d3-73af5cbeab43)

 - proc_creation_win_susp_certutil_command.yml (id: e011a729-98a6-4139-b5c4-bf6f6dd8239a)



[back](../index.md)
