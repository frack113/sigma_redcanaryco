
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: Local Account 

Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service. With a sufficient level of access, the <code>net user /add</code> command can be used to create a local account.

Such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

# MITRE
## Tactic
  - persistence


## technique
  - T1136.001


# Test : Create a new user in PowerShell
## OS
  - windows


## Description:
Creates a new user in PowerShell. Upon execution, details about the new account will be displayed in the powershell session. To verify the
new account, run "net user" in powershell or CMD and observe that there is a new user named "T1136.001_PowerShell"


# Sigma Rule
 - posh_ps_create_local_user.yml (id: 243de76f-4725-4f2e-8225-a8a69b15ad61)



[back](../index.md)
