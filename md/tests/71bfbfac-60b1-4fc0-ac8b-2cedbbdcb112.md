
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: Regsvcs/Regasm 

Adversaries may abuse Regsvcs and Regasm to proxy execution of code through a trusted Windows utility. Regsvcs and Regasm are Windows command-line utilities that are used to register .NET [Component Object Model](https://attack.mitre.org/techniques/T1559/001) (COM) assemblies. Both are digitally signed by Microsoft. (Citation: MSDN Regsvcs) (Citation: MSDN Regasm)

Both utilities may be used to bypass application control through use of attributes within the binary to specify code that should be run before registration or unregistration: <code>[ComRegisterFunction]</code> or <code>[ComUnregisterFunction]</code> respectively. The code with the registration and unregistration attributes will be executed even if the process is run under insufficient privileges and fails to execute. (Citation: LOLBAS Regsvcs)(Citation: LOLBAS Regasm)

# MITRE
## Tactic
  - defense-evasion


## technique
  - T1218.009


# Test : Regasm Uninstall Method Call Test
## OS
  - windows


## Description:
Executes the Uninstall Method, No Admin Rights Required. Upon execution, "I shouldn't really execute either." will be displayed.


## Executor
command_prompt

# Sigma Rule
 - win_susp_csc_folder.yml (id: dcaa3f04-70c3-427a-80b4-b870d73c94c4)



[back](../index.md)
