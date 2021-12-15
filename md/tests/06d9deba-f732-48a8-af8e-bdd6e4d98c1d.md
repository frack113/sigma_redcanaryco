[back](../index.md)

Cover by sigma :x: 

# Attack: InstallUtil

 Adversaries may use InstallUtil to proxy execution of code through a trusted Windows utility. InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries. (Citation: MSDN InstallUtil) InstallUtil is digitally signed by Microsoft and located in the .NET directories on a Windows system: <code>C:\Windows\Microsoft.NET\Framework\v<version>\InstallUtil.exe</code> and <code>C:\Windows\Microsoft.NET\Framework64\v<version>\InstallUtil.exe</code>.

InstallUtil may also be used to bypass application control through use of attributes within the binary that execute the class decorated with the attribute <code>[System.ComponentModel.RunInstaller(true)]</code>. (Citation: LOLBAS Installutil)

# MITRE
## Tactic
  - defense-evasion

## technique
  - T1218.004

# Test : InstallUtil Uninstall method call - '/installtype=notransaction /action=uninstall' variant

OS: ['windows']

Description:

 Executes the Uninstall Method. Upon execution, version information will be displayed the .NET framework install utility.


# Sigma

 So many other things to do...