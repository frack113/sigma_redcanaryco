# Find a test to trigger a SigmaHQ rule

[back](./index.md)

## The rules


* dns_query_win_ammyy.yml
  * T1219 [Ammyy Admin Software Execution](tests/0ae9e327-3251-465a-a53b-485d4e3f58fa.md)
* dns_query_win_gotoopener.yml
  * T1219 [GoToAssist Files Detected Test on Windows](tests/1b72b3bd-72f8-4b63-a30b-84e91b9c3578.md)
* dns_query_win_logmein.yml
  * T1219 [LogMeIn Files Detected Test on Windows](tests/d03683ec-aae0-42f9-9b4c-534780e0f8e1.md)
* dns_query_win_regsvr32_network_activity.yml
  * T1218.010 [Regsvr32 remote COM scriptlet execution](tests/c9d0c4ef-8a96-4794-a75b-3d3a5e6f2a36.md)
* file_access_win_browser_credential_stealing.yml
  * T1539 [Steal Firefox Cookies (Windows)](tests/4b437357-f4e9-4c84-9fa6-9bcee6f826aa.md)
  * T1539 [Steal Chrome Cookies (Windows)](tests/26a6b840-4943-4965-8df5-ef1f9a282440.md)
* file_delete_win_delete_appli_log.yml
  * T1070.004 [Delete TeamViewer Log Files](tests/69f50a5f-967c-4327-a5bb-e1a9a9983785.md)
* file_delete_win_delete_backup_file.yml
  * T1490 [Windows - Delete Backup Files](tests/6b1dbaf6-cc8a-4ea6-891f-6058569653bf.md)
* file_delete_win_delete_prefetch.yml
  * T1070.004 [Delete Prefetch File](tests/36f96049-0ad7-4a5f-8418-460acaeb92fb.md)
* file_delete_win_sysinternals_sdelete_file_deletion.yml
  * T1485 [Windows - Overwrite file with Sysinternals SDelete](tests/476419b5-aebf-4366-a131-ae3e8dae5fc2.md)
* file_event_win_access_susp_unattend_xml.yml
  * T1552.001 [Access unattend.xml](tests/367d4004-5fc0-446d-823f-960c74ae52c3.md)
* file_event_win_anydesk_artefact.yml
  * T1219 [AnyDesk Files Detected Test on Windows](tests/6b8b7391-5c0a-4f8c-baee-78d8ce0ce330.md)
* file_event_win_creation_new_shim_database.yml
  * T1546.011 [New shim database files created in the default shim database directory](tests/aefd6866-d753-431f-a7a4-215ca7e3f13d.md)
* file_event_win_creation_scr_binary_file.yml
  * T1546.002 [Set Arbitrary Binary as Screensaver](tests/281201e7-de41-4dc9-b73d-f288938cbb64.md)
  * T1218.011 [Rundll32 with desk.cpl](tests/83a95136-a496-423c-81d3-1c6750133917.md)
* file_event_win_creation_system_file.yml
  * T1036.003 [Masquerading - windows exe running as different windows exe](tests/c3d24a39-2bfe-4c6a-b064-90cd73896cb0.md)
  * T1036.003 [Malicious process Masquerading as LSM.exe](tests/83810c46-f45e-4485-9ab6-8ed0e9e6ed7f.md)
  * T1036.005 [Masquerade as a built-in system executable](tests/35eb8d16-9820-4423-a2a1-90c4f5edd9ca.md)
  * T1036.003 [Masquerading as Windows LSASS process](tests/5ba5a3d1-cf3c-4499-968a-a93155d1f717.md)
  * T1036.003 [Masquerading - wscript.exe running as svchost.exe](tests/24136435-c91a-4ede-9da1-8b284a1c1a23.md)
  * T1036.003 [Masquerading - non-windows exe running as windows exe](tests/bc15c13f-d121-4b1f-8c7d-28d95854d086.md)
  * T1105 [svchost writing a file to a UNC path](tests/fa5a2759-41d7-4e13-a19c-e8f28a53566f.md)
* file_event_win_creation_unquoted_service_path.yml
  * T1574.009 [Execution of program.exe as service with unquoted service path](tests/2770dea7-c50f-457b-84c4-c40a47460d9f.md)
* file_event_win_csharp_compile_artefact.yml
  * T1218.005 [Invoke HTML Application - JScript Engine with Rundll32 and Inline Protocol Handler](tests/e7e3a525-7612-4d68-a5d3-c4649181b8af.md)
  * T1134.004 [Parent PID Spoofing using PowerShell](tests/069258f4-2162-46e9-9a25-c9c6c56150d2.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement](tests/007e5672-2088-4853-a562-7490ddc19447.md)
  * T1027.004 [Dynamic C# Compile](tests/453614d8-3ba6-4147-acc0-7ec4b3e1faef.md)
  * T1127.001 [MSBuild Bypass Using Inline Tasks (VB)](tests/ab042179-c0c5-402f-9bc8-42741f5ce359.md)
  * T1036.005 [Masquerade as a built-in system executable](tests/35eb8d16-9820-4423-a2a1-90c4f5edd9ca.md)
  * T1218.005 [Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine Simulating Double Click](tests/58a193ec-131b-404e-b1ca-b35cf0b18c33.md)
  * T1134.002 [Access Token Manipulation](tests/dbf4f5a9-b8e0-46a3-9841-9ad71247239e.md)
  * T1071.004 [DNS C2](tests/e7bf9802-2e78-4db9-93b5-181b7bcd37d7.md)
  * T1218.004 [InstallUtil Uninstall method call - /U variant](tests/34428cfa-8e38-41e5-aff4-9e1f8f3a7b4b.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1218.004 [InstallUtil Install method call](tests/9f9968a6-601a-46ca-b7b7-6d4fe0f98f0b.md)
  * T1218.004 [InstallUtil Uninstall method call - '/installtype=notransaction /action=uninstall' variant](tests/06d9deba-f732-48a8-af8e-bdd6e4d98c1d.md)
  * T1218 [Invoke-ATHRemoteFXvGPUDisablementCommand base test](tests/9ebe7901-7edf-45c0-b5c7-8366300919db.md)
  * T1218.004 [InstallUtil HelpText method call](tests/5a683850-1145-4326-a0e5-e91ced3c6022.md)
  * T1127.001 [MSBuild Bypass Using Inline Tasks (C#)](tests/58742c0f-cb01-44cd-a60b-fb26e8871c93.md)
  * T1218.004 [InstallUtil evasive invocation](tests/559e6d06-bb42-4307-bff7-3b95a8254bad.md)
  * T1218.004 [CheckIfInstallable method call](tests/ffd9c807-d402-47d2-879d-f915cf2a3a94.md)
  * T1134.004 [Parent PID Spoofing - Spawn from New Process](tests/2988133e-561c-4e42-a15f-6281e6a9b2db.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Local](tests/78e95057-d429-4e66-8f82-0f060c1ac96f.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Specified Process](tests/cbbff285-9051-444a-9d17-c07cd2d230eb.md)
  * T1218.004 [InstallHelper method call](tests/d43a5bde-ae28-4c55-a850-3f4c80573503.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
  * T1219 [ScreenConnect Application Download and Install on Windows](tests/4a18cc4e-416f-4966-9a9d-75731c4684c0.md)
  * T1134.004 [Parent PID Spoofing - Spawn from svchost.exe](tests/e9f2b777-3123-430b-805d-5cedc66ab591.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Current Process](tests/14920ebd-1d61-491a-85e0-fe98efe37f25.md)
  * T1218.004 [InstallUtil class constructor method call](tests/9b7a7cfc-dd2e-43f5-a885-c0a3c270dd93.md)
  * T1055.012 [Process Hollowing using PowerShell](tests/562427b4-39ef-4e8c-af88-463a78e70b9c.md)
* file_event_win_detect_powerup_dllhijacking.yml
  * T1074.001 [Stage data from Discovery.bat](tests/107706a5-6f9f-451a-adae-bab8c667829f.md)
  * T1558.002 [Crafting Active Directory silver tickets with mimikatz](tests/385e59aa-113e-4711-84d9-f637aef01f2c.md)
  * T1547.001 [Suspicious bat file run from startup Folder](tests/5b6768e4-44d2-44f0-89da-a01d1430fd5e.md)
  * T1558.001 [Crafting Active Directory golden tickets with Rubeus](tests/e42d33cd-205c-4acf-ab59-a9f38f6bad9c.md)
  * T1558.001 [Crafting Active Directory golden tickets with mimikatz](tests/9726592a-dabc-4d4d-81cd-44070008b3af.md)
* file_event_win_gotoopener_artefact.yml
  * T1219 [GoToAssist Files Detected Test on Windows](tests/1b72b3bd-72f8-4b63-a30b-84e91b9c3578.md)
* file_event_win_hack_dumpert.yml
  * T1003.001 [Dump LSASS.exe Memory using direct system calls and API unhooking](tests/7ae7102c-a099-45c8-b985-4c7a2d05790d.md)
* file_event_win_hktl_nppspy.yml
  * T1003 [Credential Dumping with NPPSpy](tests/9e2173c0-ba26-4cdf-b0ed-8c54b27e3ad6.md)
* file_event_win_install_teamviewer_desktop.yml
  * T1219 [TeamViewer Files Detected Test on Windows](tests/8ca3b96d-8983-4a7f-b125-fc98cc0a2aa0.md)
* file_event_win_lsass_dump.yml
  * T1003.001 [Dump LSASS.exe Memory using Windows Task Manager](tests/dea6c349-f1c6-44f3-87a1-1ed33a59a607.md)
  * T1003.001 [Dump LSASS.exe Memory using direct system calls and API unhooking](tests/7ae7102c-a099-45c8-b985-4c7a2d05790d.md)
* file_event_win_lsass_memory_dump_file_creation.yml
  * T1003.001 [Dump LSASS.exe Memory using ProcDump](tests/0be2230c-9ab3-4ac2-8826-3199b9a0ebf8.md)
  * T1003.001 [Create Mini Dump of LSASS.exe using ProcDump](tests/7cede33f-0acd-44ef-9774-15511300b24b.md)
  * T1003.001 [Dump LSASS.exe Memory using comsvcs.dll](tests/2536dee2-12fb-459a-8c37-971844fa73be.md)
  * T1003.001 [Dump LSASS.exe Memory using Windows Task Manager](tests/dea6c349-f1c6-44f3-87a1-1ed33a59a607.md)
  * T1003.001 [Dump LSASS.exe using imported Microsoft DLLs](tests/86fc3f40-237f-4701-b155-81c01c48d697.md)
  * T1003.001 [Dump LSASS.exe Memory using Out-Minidump.ps1](tests/6502c8f0-b775-4dbd-9193-1298f56b6781.md)
* file_event_win_macro_file.yml
  * T1566.001 [Download Macro-Enabled Phishing Attachment](tests/114ccff9-ae6d-4547-9ead-4cd69f687306.md)
* file_event_win_new_src_file.yml
  * T1218.011 [Rundll32 with desk.cpl](tests/83a95136-a496-423c-81d3-1c6750133917.md)
* file_event_win_outlook_c2_macro_creation.yml
  * T1137 [Office Application Startup - Outlook as a C2](tests/bfe6ac15-c50b-4c4f-a186-0fc6b8ba936c.md)
* file_event_win_powershell_startup_shortcuts.yml
  * T1547.009 [Create shortcut to cmd in startup folders](tests/cfdc954d-4bb0-4027-875b-a1893ce406f2.md)
  * T1547.001 [Add Executable Shortcut Link to User Startup Folder](tests/24e55612-85f6-4bd6-ae74-a73d02e3441d.md)
* file_event_win_screenconnect_artefact.yml
  * T1219 [ScreenConnect Application Download and Install on Windows](tests/4a18cc4e-416f-4966-9a9d-75731c4684c0.md)
* file_event_win_script_creation_by_office_using_file_ext.yml
  * T1204.002 [Office launching .bat file from AppData](tests/9215ea92-1ded-41b7-9cd6-79f9a78397aa.md)
  * T1055.012 [RunPE via VBA](tests/3ad4a037-1598-4136-837c-4027e4fa319b.md)
  * T1564 [Extract binary files via VBA](tests/6afe288a-8a8b-4d33-a629-8d03ba9dad3a.md)
  * T1204.002 [Excel 4 Macro](tests/4ea1fc97-8a46-4b4e-ba48-af43d2a98052.md)
* file_event_win_startup_folder_file_write.yml
  * T1547.001 [Suspicious vbs file run from startup Folder](tests/2cb98256-625e-4da9-9d44-f2e5f90b8bd5.md)
  * T1547.001 [Suspicious jse file run from startup Folder](tests/dade9447-791e-4c8f-b04b-3a35855dfa06.md)
  * T1547.009 [Shortcut Modification](tests/ce4fc678-364f-4282-af16-2fb4c78005ce.md)
  * T1547.001 [Suspicious bat file run from startup Folder](tests/5b6768e4-44d2-44f0-89da-a01d1430fd5e.md)
  * T1547.009 [Create shortcut to cmd in startup folders](tests/cfdc954d-4bb0-4027-875b-a1893ce406f2.md)
* file_event_win_susp_clr_logs.yml
  * T1036.005 [Masquerade as a built-in system executable](tests/35eb8d16-9820-4423-a2a1-90c4f5edd9ca.md)
  * T1219 [ScreenConnect Application Download and Install on Windows](tests/4a18cc4e-416f-4966-9a9d-75731c4684c0.md)
  * T1218.010 [Regsvr32 local DLL execution](tests/08ffca73-9a3d-471a-aeb0-68b4aa3ab37b.md)
  * T1218 [Renamed Microsoft.Workflow.Compiler.exe Payload Executions](tests/4cc40fd7-87b8-4b16-b2d7-57534b86b911.md)
* file_event_win_susp_desktop_txt.yml
  * T1486 [PureLocker Ransom Note](tests/649349c7-9abf-493b-a7a2-b1aa4d141528.md)
* file_event_win_susp_dropper.yml
  * T1562.006 [Disable Powershell ETW Provider - Windows](tests/6f118276-121d-4c09-bb58-a8fb4a72ee84.md)
* file_event_win_tool_psexec.yml
  * T1207 [DCShadow (Active Directory)](tests/0f4c5eb0-98a0-4496-9c3d-656b4f2bc8f6.md)
  * T1550.003 [Rubeus Kerberos Pass The Ticket](tests/a2fc4ec5-12c6-4fb4-b661-961f23f359cb.md)
  * T1562.006 [Disable Powershell ETW Provider - Windows](tests/6f118276-121d-4c09-bb58-a8fb4a72ee84.md)
  * T1003.004 [Dumping LSA Secrets](tests/55295ab0-a703-433b-9ca4-ae13807de12f.md)
  * T1021.002 [Copy and Execute File with PsExec](tests/0eb03d41-79e4-4393-8e57-6344856be1cf.md)
  * T1569.002 [Use PsExec to execute a command on a remote host](tests/873106b7-cfed-454b-8680-fa9f6400431c.md)
* file_event_win_webshell_creation_detect.yml
  * T1505.003 [Web Shell Written to Disk](tests/0a2ce662-1efa-496f-a472-2fe7b080db16.md)
* file_event_win_win_shell_write_susp_directory.yml
  * T1105 [certutil download (verifyctl)](tests/ffd492e3-0455-4518-9fb1-46527c9f241b.md)
  * T1140 [Deobfuscate/Decode Files Or Information](tests/dc6fe391-69e6-4506-bd06-ea5eeb4082f8.md)
  * T1564.004 [Store file in Alternate Data Stream (ADS)](tests/2ab75061-f5d5-4c1a-b666-ba2a50df5b02.md)
  * T1218.005 [Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md)
  * T1003.002 [dump volume shadow copy hives with certutil](tests/eeb9751a-d598-42d3-b11c-c122d9c3f6c7.md)
  * T1105 [certutil download (urlcache)](tests/dd3b61dd-7bbc-48cd-ab51-49ad1a776df0.md)
  * T1564.004 [Alternate Data Streams (ADS)](tests/8822c3b0-d9f9-4daf-a043-49f4602364f4.md)
  * T1218.005 [Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject](tests/1483fab9-4f52-4217-a9ce-daa9d7747cae.md)
  * T1220 [WMIC bypass using remote XSL file](tests/7f5be499-33be-4129-a560-66021f379b9b.md)
  * T1059.001 [Powershell invoke mshta.exe download](tests/8a2ad40b-12c7-4b25-8521-2737b0a415af.md)
* file_event_win_writing_local_admin_share.yml
  * T1021.002 [Execute command writing output to local Admin Share](tests/d41aaab5-bdfe-431d-a3d5-c29e9136ff46.md)
* file_rename_win_not_dll_to_dll.yml
  * T1036 [Malware Masquerading and Execution from Zip File](tests/4449c89b-ec82-43a4-89c1-91e2f1abeecc.md)
* image_load_alternate_powershell_hosts_moduleload.yml
  * T1055.012 [RunPE via VBA](tests/3ad4a037-1598-4136-837c-4027e4fa319b.md)
  * T1036.003 [Masquerading - powershell.exe running as taskhostw.exe](tests/ac9d0fc3-8aa8-4ab5-b11f-682cd63b40aa.md)
  * T1574.001 [DLL Search Order Hijacking - amsi.dll](tests/8549ad4b-b5df-4a2d-a3d7-2aee9e7052a3.md)
* image_load_in_memory_powershell.yml
  * T1055.012 [RunPE via VBA](tests/3ad4a037-1598-4136-837c-4027e4fa319b.md)
  * T1036.003 [Masquerading - powershell.exe running as taskhostw.exe](tests/ac9d0fc3-8aa8-4ab5-b11f-682cd63b40aa.md)
  * T1574.001 [DLL Search Order Hijacking - amsi.dll](tests/8549ad4b-b5df-4a2d-a3d7-2aee9e7052a3.md)
* image_load_susp_advapi32_dll.yml
  * T1562.002 [Makes Eventlog blind with Phant0m](tests/3ddf3d03-f5d6-462a-ad76-2c5ff7b6d741.md)
* image_load_susp_office_dotnet_assembly_dll_load.yml
  * T1055.012 [RunPE via VBA](tests/3ad4a037-1598-4136-837c-4027e4fa319b.md)
* image_load_susp_office_dotnet_clr_dll_load.yml
  * T1055.012 [RunPE via VBA](tests/3ad4a037-1598-4136-837c-4027e4fa319b.md)
* image_load_susp_office_dotnet_gac_dll_load.yml
  * T1055.012 [RunPE via VBA](tests/3ad4a037-1598-4136-837c-4027e4fa319b.md)
* image_load_susp_python_image_load.yml
  * T1555.003 [LaZagne - Credentials from Browser](tests/9a2915b3-3954-4cce-8c76-00fbf4dbd014.md)
  * T1550.002 [crackmapexec Pass the Hash](tests/eb05b028-16c8-4ad8-adea-6f5b219da9a9.md)
* image_load_susp_system_drawing_load.yml
  * T1218.010 [Regsvr32 Silent DLL Install Call DllRegisterServer](tests/9d71c492-ea2e-4c08-af16-c6994cdf029f.md)
  * T1219 [ScreenConnect Application Download and Install on Windows](tests/4a18cc4e-416f-4966-9a9d-75731c4684c0.md)
  * T1218 [Renamed Microsoft.Workflow.Compiler.exe Payload Executions](tests/4cc40fd7-87b8-4b16-b2d7-57534b86b911.md)
* image_load_susp_winword_vbadll_load.yml
  * T1566.001 [Word spawned a command shell and used an IP address in the command line](tests/cbb6799a-425c-4f83-9194-5447a909d67f.md)
  * T1204.002 [OSTAP JS version](tests/add560ef-20d6-4011-a937-2c340f930911.md)
  * T1204.002 [Office launching .bat file from AppData](tests/9215ea92-1ded-41b7-9cd6-79f9a78397aa.md)
  * T1055.012 [RunPE via VBA](tests/3ad4a037-1598-4136-837c-4027e4fa319b.md)
  * T1564 [Extract binary files via VBA](tests/6afe288a-8a8b-4d33-a629-8d03ba9dad3a.md)
  * T1053.005 [Task Scheduler via VBA](tests/ecd3fa21-7792-41a2-8726-2c5c673414d3.md)
  * T1204.002 [Headless Chrome code execution via VBA](tests/a19ee671-ed98-4e9d-b19c-d1954a51585a.md)
  * T1204.002 [Maldoc choice flags command execution](tests/0330a5d2-a45a-4272-a9ee-e364411c4b18.md)
  * T1204.002 [Office Generic Payload Download](tests/5202ee05-c420-4148-bf5e-fd7f7d24850c.md)
  * T1204.002 [Excel 4 Macro](tests/4ea1fc97-8a46-4b4e-ba48-af43d2a98052.md)
  * T1204.002 [OSTap Style Macro Execution](tests/8bebc690-18c7-4549-bc98-210f7019efff.md)
  * T1070.001 [Clear Event Logs via VBA](tests/1b682d84-f075-4f93-9a89-8a8de19ffd6e.md)
  * T1555 [Extract Windows Credential Manager via VBA](tests/234f9b7c-b53d-4f32-897b-b880a6c9ea7b.md)
  * T1059.005 [Extract Memory via VBA](tests/8faff437-a114-4547-9a60-749652a03df6.md)
  * T1055 [Shellcode execution via VBA](tests/1c91e740-1729-4329-b779-feba6e71d048.md)
  * T1221 [WINWORD Remote Template Injection](tests/1489e08a-82c7-44ee-b769-51b72d03521d.md)
  * T1059.005 [Encoded VBS code execution](tests/e8209d5f-e42d-45e6-9c2f-633ac4f1eefa.md)
  * T1115 [Collect Clipboard Data via VBA](tests/9c8d5a72-9c98-48d3-b9bf-da2cc43bdf52.md)
* image_load_suspicious_dbghelp_dbgcore_load.yml
  * T1566.001 [Word spawned a command shell and used an IP address in the command line](tests/cbb6799a-425c-4f83-9194-5447a909d67f.md)
  * T1055.004 [Process Injection via C#](tests/611b39b7-e243-4c81-87a4-7145a90358b1.md)
  * T1055.012 [RunPE via VBA](tests/3ad4a037-1598-4136-837c-4027e4fa319b.md)
  * T1564 [Extract binary files via VBA](tests/6afe288a-8a8b-4d33-a629-8d03ba9dad3a.md)
  * T1204.002 [Office Generic Payload Download](tests/5202ee05-c420-4148-bf5e-fd7f7d24850c.md)
  * T1562.002 [Kill Event Log Service Threads](tests/41ac52ba-5d5e-40c0-b267-573ed90489bd.md)
  * T1003.001 [Dump LSASS.exe Memory using comsvcs.dll](tests/2536dee2-12fb-459a-8c37-971844fa73be.md)
  * T1070.001 [Clear Event Logs via VBA](tests/1b682d84-f075-4f93-9a89-8a8de19ffd6e.md)
  * T1003 [Dump svchost.exe to gather RDP credentials](tests/d400090a-d8ca-4be0-982e-c70598a23de9.md)
  * T1574.002 [DLL Side-Loading using the Notepad++ GUP.exe binary](tests/65526037-7079-44a9-bda1-2cb624838040.md)
  * T1003.001 [Dump LSASS.exe Memory using Out-Minidump.ps1](tests/6502c8f0-b775-4dbd-9193-1298f56b6781.md)
* image_load_suspicious_vss_ps_load.yml
  * T1003.002 [dump volume shadow copy hives with certutil](tests/eeb9751a-d598-42d3-b11c-c122d9c3f6c7.md)
  * T1003.003 [Create Volume Shadow Copy with WMI](tests/224f7de0-8f0a-4a94-b5d8-989b036c86da.md)
  * T1003.003 [Create Volume Shadow Copy remotely (WMI) with esentutl](tests/21c7bf80-3e8b-40fa-8f9d-f5b194ff2865.md)
  * T1003.002 [esentutl.exe SAM copy](tests/a90c2f4d-6726-444e-99d2-a00cd7c20480.md)
* image_load_uipromptforcreds_dlls.yml
  * T1204.002 [Excel 4 Macro](tests/4ea1fc97-8a46-4b4e-ba48-af43d2a98052.md)
* image_load_wmic_remote_xsl_scripting_dlls.yml
  * T1119 [Recon information for export with Command Prompt](tests/aa1180e2-f329-4e1e-8625-2472ec0bfaf3.md)
  * T1047 [WMI Reconnaissance List Remote Services](tests/0fd48ef7-d890-4e93-a533-f7dedd5191d3.md)
  * T1033 [System Owner/User Discovery](tests/4c4959bf-addf-4b4a-be86-8d09cc1857aa.md)
  * T1220 [WMIC bypass using remote XSL file](tests/7f5be499-33be-4129-a560-66021f379b9b.md)
  * T1220 [WMIC bypass using local XSL file](tests/1b237334-3e21-4a0c-8178-b8c996124988.md)
* image_load_wsman_provider_image_load.yml
  * T1021.006 [Enable Windows Remote Management](tests/9059e8de-3d7d-4954-a322-46161880b9cf.md)
  * T1021.006 [Invoke-Command](tests/5295bd61-bd7e-4744-9d52-85962a4cf2d6.md)
  * T1059.001 [PowerShell Session Creation and Use](tests/7c1acec2-78fa-4305-a3e0-db2a54cddecd.md)
* net_connection_win_binary_github_com.yml
  * T1105 [Windows - PowerShell Download](tests/42dc4460-9aa6-45d3-b1a6-3955d34e1fe8.md)
  * T1095 [Powercat C2](tests/3e0e0e7f-6aa2-4a61-b61d-526c2cc9330e.md)
  * T1218.011 [Rundll32 execute JavaScript Remote Payload With GetObject](tests/cf3bdb9a-dd11-4b6c-b0d0-9e22b68a71be.md)
  * T1105 [certutil download (verifyctl)](tests/ffd492e3-0455-4518-9fb1-46527c9f241b.md)
  * T1059.001 [Run Bloodhound from Memory using Download Cradle](tests/bf8c1441-4674-4dab-8e4e-39d93d08f9b7.md)
  * T1055.012 [RunPE via VBA](tests/3ad4a037-1598-4136-837c-4027e4fa319b.md)
  * T1564 [Extract binary files via VBA](tests/6afe288a-8a8b-4d33-a629-8d03ba9dad3a.md)
  * T1095 [ICMP C2](tests/0268e63c-e244-42db-bef7-72a9e59fc1fc.md)
  * T1218.005 [Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md)
  * T1204.002 [Office Generic Payload Download](tests/5202ee05-c420-4148-bf5e-fd7f7d24850c.md)
  * T1071.004 [DNS C2](tests/e7bf9802-2e78-4db9-93b5-181b7bcd37d7.md)
  * T1566.001 [Download Macro-Enabled Phishing Attachment](tests/114ccff9-ae6d-4547-9ead-4cd69f687306.md)
  * T1059.001 [Powershell MsXml COM object - with prompt](tests/388a7340-dbc1-4c9d-8e59-b75ad8c6d5da.md)
  * T1059.001 [Invoke-AppPathBypass](tests/06a220b6-7e29-4bd8-9d07-5b4d86742372.md)
  * T1059.001 [PowerUp Invoke-AllChecks](tests/1289f78d-22d2-4590-ac76-166737e1811b.md)
  * T1105 [File Download via PowerShell](tests/54a4daf1-71df-4383-9ba7-f1a295d8b6d2.md)
  * T1557.001 [LLMNR Poisoning with Inveigh (PowerShell)](tests/deecd55f-afe0-4a62-9fba-4d1ba2deb321.md)
  * T1134.001 [Named pipe client impersonation](tests/90db9e27-8e7c-4c04-b602-a45927884966.md)
  * T1069.002 [Get-DomainGroupMember with PowerView](tests/46352f40-f283-4fe5-b56d-d9a71750e145.md)
  * T1615 [Get-DomainGPO to display group policy information via PowerView](tests/4e524c4e-0e02-49aa-8df5-93f3f7959b9f.md)
  * T1218.005 [Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject](tests/1483fab9-4f52-4217-a9ce-daa9d7747cae.md)
  * T1218.007 [Msiexec.exe - Execute Remote MSI file](tests/44a4bedf-ffe3-452e-bee4-6925ab125662.md)
  * T1553.004 [Add Root Certificate to CurrentUser Certificate Store](tests/ca20a3f1-42b5-4e21-ad3f-1049199ec2e0.md)
  * T1218.005 [Mshta Executes Remote HTML Application (HTA)](tests/c4b97eeb-5249-4455-a607-59f95485cb45.md)
  * T1134.001 [`SeDebugPrivilege` token duplication](tests/34f0a430-9d04-4d98-bcb5-1989f14719f0.md)
  * T1550.002 [Invoke-WMIExec Pass the Hash](tests/f8757545-b00a-4e4e-8cfb-8cfb961ee713.md)
  * T1055 [Shellcode execution via VBA](tests/1c91e740-1729-4329-b779-feba6e71d048.md)
  * T1220 [WMIC bypass using remote XSL file](tests/7f5be499-33be-4129-a560-66021f379b9b.md)
  * T1059.001 [Powershell XML requests](tests/4396927f-e503-427b-b023-31049b9b09a6.md)
  * T1087.002 [Get-DomainUser with PowerView](tests/93662494-5ed7-4454-a04c-8c8372808ac2.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
  * T1069.002 [Get-DomainGroup with PowerView](tests/5a8a181c-2c8e-478d-a943-549305a01230.md)
* net_connection_win_excel_outbound_network_connection.yml
  * T1204.002 [Excel 4 Macro](tests/4ea1fc97-8a46-4b4e-ba48-af43d2a98052.md)
* net_connection_win_imewdbld.yml
  * T1105 [Download a file with IMEWDBLD.exe](tests/1a02df58-09af-4064-a765-0babe1a0d1e2.md)
* net_connection_win_msiexec.yml
  * T1219 [LogMeIn Files Detected Test on Windows](tests/d03683ec-aae0-42f9-9b4c-534780e0f8e1.md)
  * T1218.007 [Msiexec.exe - Execute Remote MSI file](tests/44a4bedf-ffe3-452e-bee4-6925ab125662.md)
  * T1219 [ScreenConnect Application Download and Install on Windows](tests/4a18cc4e-416f-4966-9a9d-75731c4684c0.md)
* net_connection_win_powershell_network_connection.yml
  * T1219 [GoToAssist Files Detected Test on Windows](tests/1b72b3bd-72f8-4b63-a30b-84e91b9c3578.md)
  * T1105 [Windows - PowerShell Download](tests/42dc4460-9aa6-45d3-b1a6-3955d34e1fe8.md)
  * T1095 [Powercat C2](tests/3e0e0e7f-6aa2-4a61-b61d-526c2cc9330e.md)
  * T1059.001 [Run Bloodhound from Memory using Download Cradle](tests/bf8c1441-4674-4dab-8e4e-39d93d08f9b7.md)
  * T1055.012 [RunPE via VBA](tests/3ad4a037-1598-4136-837c-4027e4fa319b.md)
  * T1020 [IcedID Botnet HTTP PUT](tests/9c780d3d-3a14-4278-8ee5-faaeb2ccfbe0.md)
  * T1564 [Extract binary files via VBA](tests/6afe288a-8a8b-4d33-a629-8d03ba9dad3a.md)
  * T1016 [List Open Egress Ports](tests/4b467538-f102-491d-ace7-ed487b853bf5.md)
  * T1095 [ICMP C2](tests/0268e63c-e244-42db-bef7-72a9e59fc1fc.md)
  * T1059.001 [Run BloodHound from local disk](tests/a21bb23e-e677-4ee7-af90-6931b57b6350.md)
  * T1201 [Get-DomainPolicy with PowerView](tests/3177f4da-3d4b-4592-8bdc-aa23d0b2e843.md)
  * T1033 [Find computers where user has session - Stealth mode (PowerView)](tests/29857f27-a36f-4f7e-8084-4557cd6207ca.md)
  * T1204.002 [Office Generic Payload Download](tests/5202ee05-c420-4148-bf5e-fd7f7d24850c.md)
  * T1069.002 [Enumerate Active Directory Groups with Get-AdGroup](tests/3d1fcd2a-e51c-4cbe-8d84-9a843bad8dc8.md)
  * T1069.002 [Get-ADUser Enumeration using UserAccountControl flags (AS-REP Roasting)](tests/43fa81fb-34bb-4b5f-867b-03c7dbe0e3d8.md)
  * T1087.002 [Enumerate Linked Policies In ADSISearcher Discovery](tests/7ab0205a-34e4-4a44-9b04-e1541d1a57be.md)
  * T1071.004 [DNS C2](tests/e7bf9802-2e78-4db9-93b5-181b7bcd37d7.md)
  * T1110.003 [Password spray all Active Directory domain users with a single password via LDAP against domain controller (NTLM or Kerberos)](tests/f14d956a-5b6e-4a93-847f-0c415142f07d.md)
  * T1566.001 [Download Macro-Enabled Phishing Attachment](tests/114ccff9-ae6d-4547-9ead-4cd69f687306.md)
  * T1059.001 [Powershell MsXml COM object - with prompt](tests/388a7340-dbc1-4c9d-8e59-b75ad8c6d5da.md)
  * T1059.001 [Invoke-AppPathBypass](tests/06a220b6-7e29-4bd8-9d07-5b4d86742372.md)
  * T1059.001 [PowerUp Invoke-AllChecks](tests/1289f78d-22d2-4590-ac76-166737e1811b.md)
  * T1074.001 [Stage data from Discovery.bat](tests/107706a5-6f9f-451a-adae-bab8c667829f.md)
  * T1558.003 [Request for service tickets](tests/3f987809-3681-43c8-bcd8-b3ff3a28533a.md)
  * T1105 [File Download via PowerShell](tests/54a4daf1-71df-4383-9ba7-f1a295d8b6d2.md)
  * T1557.001 [LLMNR Poisoning with Inveigh (PowerShell)](tests/deecd55f-afe0-4a62-9fba-4d1ba2deb321.md)
  * T1219 [LogMeIn Files Detected Test on Windows](tests/d03683ec-aae0-42f9-9b4c-534780e0f8e1.md)
  * T1087.002 [Enumerate Active Directory Users with ADSISearcher](tests/02e8be5a-3065-4e54-8cc8-a14d138834d3.md)
  * T1071.001 [Malicious User Agents - Powershell](tests/81c13829-f6c9-45b8-85a6-053366d55297.md)
  * T1018 [Remote System Discovery - nslookup](tests/baa01aaa-5e13-45ec-8a0d-e46c93c9760f.md)
  * T1134.001 [Named pipe client impersonation](tests/90db9e27-8e7c-4c04-b602-a45927884966.md)
  * T1204.002 [Potentially Unwanted Applications (PUA)](tests/02f35d62-9fdc-4a97-b899-a5d9a876d295.md)
  * T1069.002 [Get-DomainGroupMember with PowerView](tests/46352f40-f283-4fe5-b56d-d9a71750e145.md)
  * T1615 [Get-DomainGPO to display group policy information via PowerView](tests/4e524c4e-0e02-49aa-8df5-93f3f7959b9f.md)
  * T1048 [DNSExfiltration (doh)](tests/c943d285-ada3-45ca-b3aa-7cd6500c6a48.md)
  * T1553.004 [Add Root Certificate to CurrentUser Certificate Store](tests/ca20a3f1-42b5-4e21-ad3f-1049199ec2e0.md)
  * T1132.001 [XOR Encoded data.](tests/c3ed6d2a-e3ad-400d-ad78-bbfdbfeacc08.md)
  * T1201 [Enumerate Active Directory Password Policy with get-addefaultdomainpasswordpolicy](tests/b2698b33-984c-4a1c-93bb-e4ba72a0babb.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Remote](tests/cab413d8-9e4a-4b8d-9b84-c985bd73a442.md)
  * T1110.001 [Brute Force Credentials of single Active Directory domain user via LDAP against domain controller (NTLM or Kerberos)](tests/c2969434-672b-4ec8-8df0-bbb91f40e250.md)
  * T1219 [ScreenConnect Application Download and Install on Windows](tests/4a18cc4e-416f-4966-9a9d-75731c4684c0.md)
  * T1218.005 [Mshta Executes Remote HTML Application (HTA)](tests/c4b97eeb-5249-4455-a607-59f95485cb45.md)
  * T1134.001 [`SeDebugPrivilege` token duplication](tests/34f0a430-9d04-4d98-bcb5-1989f14719f0.md)
  * T1550.002 [Invoke-WMIExec Pass the Hash](tests/f8757545-b00a-4e4e-8cfb-8cfb961ee713.md)
  * T1055 [Shellcode execution via VBA](tests/1c91e740-1729-4329-b779-feba6e71d048.md)
  * T1087.002 [Enumerate Root Domain linked policies Discovery](tests/00c652e2-0750-4ca6-82ff-0204684a6fe4.md)
  * T1059.001 [Powershell XML requests](tests/4396927f-e503-427b-b023-31049b9b09a6.md)
  * T1087.002 [Get-DomainUser with PowerView](tests/93662494-5ed7-4454-a04c-8c8372808ac2.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
  * T1041 [C2 Data Exfiltration](tests/d1253f6e-c29b-49dc-b466-2147a6191932.md)
  * T1069.002 [Get-DomainGroup with PowerView](tests/5a8a181c-2c8e-478d-a943-549305a01230.md)
  * T1219 [TeamViewer Files Detected Test on Windows](tests/8ca3b96d-8983-4a7f-b125-fc98cc0a2aa0.md)
* net_connection_win_python.yml
  * T1046 [Port Scan using python](tests/6ca45b04-9f15-4424-b9d3-84a217285a5c.md)
* net_connection_win_regsvr32_network_activity.yml
  * T1218.010 [Regsvr32 remote COM scriptlet execution](tests/c9d0c4ef-8a96-4794-a75b-3d3a5e6f2a36.md)
* net_connection_win_remote_powershell_session_network.yml
  * T1021.006 [Invoke-Command](tests/5295bd61-bd7e-4744-9d52-85962a4cf2d6.md)
  * T1105 [Windows - BITSAdmin BITS Download](tests/a1921cd3-9a2d-47d5-a891-f1d0f2a7a31b.md)
  * T1059.001 [PowerShell Session Creation and Use](tests/7c1acec2-78fa-4305-a3e0-db2a54cddecd.md)
* net_connection_win_rundll32_net_connections.yml
  * T1218.011 [Rundll32 execute JavaScript Remote Payload With GetObject](tests/cf3bdb9a-dd11-4b6c-b0d0-9e22b68a71be.md)
  * T1218.011 [Rundll32 ieadvpack.dll Execution](tests/5e46a58e-cbf6-45ef-a289-ed7754603df9.md)
  * T1218.011 [Rundll32 advpack.dll Execution](tests/d91cae26-7fc1-457b-a854-34c8aad48c89.md)
* net_connection_win_susp_outbound_smtp_connections.yml
  * T1048.003 [Exfiltration Over Alternative Protocol - SMTP](tests/ec3a835e-adca-4c7c-88d2-853b69c11bb9.md)
* net_connection_win_susp_rdp.yml
  * T1016 [List Open Egress Ports](tests/4b467538-f102-491d-ace7-ed487b853bf5.md)
* net_connection_win_suspicious_outbound_kerberos_connection.yml
  * T1016 [List Open Egress Ports](tests/4b467538-f102-491d-ace7-ed487b853bf5.md)
* pipe_created_tool_psexec.yml
  * T1207 [DCShadow (Active Directory)](tests/0f4c5eb0-98a0-4496-9c3d-656b4f2bc8f6.md)
  * T1021.002 [Copy and Execute File with PsExec](tests/0eb03d41-79e4-4393-8e57-6344856be1cf.md)
  * T1569.002 [Use PsExec to execute a command on a remote host](tests/873106b7-cfed-454b-8680-fa9f6400431c.md)
* posh_pm_alternate_powershell_hosts.yml
  * T1055.012 [RunPE via VBA](tests/3ad4a037-1598-4136-837c-4027e4fa319b.md)
  * T1204.002 [Office Generic Payload Download](tests/5202ee05-c420-4148-bf5e-fd7f7d24850c.md)
  * T1204.002 [Office Generic Payload Download](tests/5202ee05-c420-4148-bf5e-fd7f7d24850c.md)
  * T1021.006 [Invoke-Command](tests/5295bd61-bd7e-4744-9d52-85962a4cf2d6.md)
  * T1036.003 [Masquerading - powershell.exe running as taskhostw.exe](tests/ac9d0fc3-8aa8-4ab5-b11f-682cd63b40aa.md)
* posh_pm_bad_opsec_artifacts.yml
  * T1033 [Find computers where user has session - Stealth mode (PowerView)](tests/29857f27-a36f-4f7e-8084-4557cd6207ca.md)
  * T1562.002 [Kill Event Log Service Threads](tests/41ac52ba-5d5e-40c0-b267-573ed90489bd.md)
  * T1558.003 [Request for service tickets](tests/3f987809-3681-43c8-bcd8-b3ff3a28533a.md)
  * T1558.003 [Rubeus kerberoast](tests/14625569-6def-4497-99ac-8e7817105b55.md)
  * T1558.003 [Rubeus kerberoast](tests/14625569-6def-4497-99ac-8e7817105b55.md)
  * T1134.001 [Named pipe client impersonation](tests/90db9e27-8e7c-4c04-b602-a45927884966.md)
  * T1615 [Get-DomainGPO to display group policy information via PowerView](tests/4e524c4e-0e02-49aa-8df5-93f3f7959b9f.md)
  * T1553.004 [Add Root Certificate to CurrentUser Certificate Store](tests/ca20a3f1-42b5-4e21-ad3f-1049199ec2e0.md)
  * T1134.001 [`SeDebugPrivilege` token duplication](tests/34f0a430-9d04-4d98-bcb5-1989f14719f0.md)
  * T1550.002 [Invoke-WMIExec Pass the Hash](tests/f8757545-b00a-4e4e-8cfb-8cfb961ee713.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
* posh_pm_clear_powershell_history.yml
  * T1070.003 [Prevent Powershell History Logging](tests/2f898b81-3e97-4abb-bc3f-a95138988370.md)
* posh_pm_get_clipboard.yml
  * T1115 [Execute Commands from Clipboard using PowerShell](tests/d6dc21af-bec9-4152-be86-326b6babd416.md)
* posh_pm_powercat.yml
  * T1095 [Powercat C2](tests/3e0e0e7f-6aa2-4a61-b61d-526c2cc9330e.md)
* posh_pm_susp_athremotefxvgpudisablementcommand.yml
  * T1218 [Invoke-ATHRemoteFXvGPUDisablementCommand base test](tests/9ebe7901-7edf-45c0-b5c7-8366300919db.md)
* posh_pm_susp_get_nettcpconnection.yml
  * T1003 [Dump svchost.exe to gather RDP credentials](tests/d400090a-d8ca-4be0-982e-c70598a23de9.md)
  * T1049 [System Network Connections Discovery with PowerShell](tests/f069f0f1-baad-4831-aa2b-eddac4baac4a.md)
* posh_pm_susp_zip_compress.yml
  * T1074.001 [Zip a Folder with PowerShell for Staging in Temp](tests/a57fbe4b-3440-452a-88a7-943531ac872a.md)
* posh_pm_suspicious_ad_group_reco.yml
  * T1069.002 [Enumerate Active Directory Groups with Get-AdGroup](tests/3d1fcd2a-e51c-4cbe-8d84-9a843bad8dc8.md)
  * T1069.002 [Get-ADUser Enumeration using UserAccountControl flags (AS-REP Roasting)](tests/43fa81fb-34bb-4b5f-867b-03c7dbe0e3d8.md)
  * T1069.002 [Enumerate Users Not Requiring Pre Auth (ASRepRoast)](tests/870ba71e-6858-4f6d-895c-bb6237f6121b.md)
  * T1069.002 [Permission Groups Discovery PowerShell (Domain)](tests/6d5d8c96-3d2a-4da9-9d6d-9a9d341899a7.md)
* posh_pm_suspicious_download.yml
  * T1105 [Windows - PowerShell Download](tests/42dc4460-9aa6-45d3-b1a6-3955d34e1fe8.md)
  * T1095 [Powercat C2](tests/3e0e0e7f-6aa2-4a61-b61d-526c2cc9330e.md)
  * T1095 [ICMP C2](tests/0268e63c-e244-42db-bef7-72a9e59fc1fc.md)
  * T1071.004 [DNS C2](tests/e7bf9802-2e78-4db9-93b5-181b7bcd37d7.md)
* posh_pm_suspicious_invocation_specific.yml
  * T1095 [Powercat C2](tests/3e0e0e7f-6aa2-4a61-b61d-526c2cc9330e.md)
  * T1059.001 [Run Bloodhound from Memory using Download Cradle](tests/bf8c1441-4674-4dab-8e4e-39d93d08f9b7.md)
  * T1095 [ICMP C2](tests/0268e63c-e244-42db-bef7-72a9e59fc1fc.md)
  * T1071.004 [DNS C2](tests/e7bf9802-2e78-4db9-93b5-181b7bcd37d7.md)
  * T1059.001 [Invoke-AppPathBypass](tests/06a220b6-7e29-4bd8-9d07-5b4d86742372.md)
  * T1615 [Get-DomainGPO to display group policy information via PowerView](tests/4e524c4e-0e02-49aa-8df5-93f3f7959b9f.md)
  * T1003.001 [Powershell Mimikatz](tests/66fb0bc1-3c3f-47e9-a298-550ecfefacbc.md)
  * T1547.001 [PowerShell Registry RunOnce](tests/eb44f842-0457-4ddc-9b92-c4caa144ac42.md)
  * T1059.001 [Obfuscation Tests](tests/4297c41a-8168-4138-972d-01f3ee92c804.md)
  * T1059.001 [Mimikatz](tests/f3132740-55bc-48c4-bcc0-758a459cd027.md)
  * T1003.001 [Dump LSASS.exe Memory using Out-Minidump.ps1](tests/6502c8f0-b775-4dbd-9193-1298f56b6781.md)
* posh_pm_suspicious_local_group_reco.yml
  * T1098 [Admin Account Manipulate](tests/5598f7cb-cf43-455e-883a-f6008c5d46af.md)
  * T1087.001 [Enumerate all accounts via PowerShell (Local)](tests/ae4b6361-b5f8-46cb-a3f9-9cf108ccfe7b.md)
  * T1087.002 [Enumerate Linked Policies In ADSISearcher Discovery](tests/7ab0205a-34e4-4a44-9b04-e1541d1a57be.md)
  * T1069.001 [WMIObject Group Discovery](tests/69119e58-96db-4110-ad27-954e48f3bb13.md)
  * T1098 [Password Change on Directory Service Restore Mode (DSRM) Account](tests/d5b886d9-d1c7-4b6e-a7b0-460041bf2823.md)
  * T1098 [Domain Account and Group Manipulate](tests/a55a22e9-a3d3-42ce-bd48-2653adb8f7a9.md)
  * T1087.002 [Enumerate all accounts via PowerShell (Domain)](tests/8b8a6449-be98-4f42-afd2-dedddc7453b2.md)
  * T1087.002 [Enumerate Root Domain linked policies Discovery](tests/00c652e2-0750-4ca6-82ff-0204684a6fe4.md)
  * T1218.005 [Mshta executes VBScript to execute malicious command](tests/906865c3-e05f-4acc-85c4-fbc185455095.md)
  * T1069.001 [Permission Groups Discovery PowerShell (Local)](tests/a580462d-2c19-4bc7-8b9a-57a41b7d3ba4.md)
* posh_pm_suspicious_smb_share_reco.yml
  * T1135 [Network Share Discovery PowerShell](tests/1b0814d1-bb24-402d-9615-1b20c50733fb.md)
  * T1070.005 [Remove Network Share PowerShell](tests/0512d214-9512-4d22-bde7-f37e058259b3.md)
* posh_ps_access_to_browser_login_data.yml
  * T1555.003 [Simulating access to Windows Firefox Login Data](tests/eb8da98a-2e16-4551-b3dd-83de49baa14c.md)
  * T1555.003 [Simulating access to Opera Login Data](tests/28498c17-57e4-495a-b0be-cc1e36de408b.md)
  * T1555.003 [Simulating access to Windows Edge Login Data](tests/a6a5ec26-a2d1-4109-9d35-58b867689329.md)
* posh_ps_access_to_chrome_login_data.yml
  * T1555.003 [Simulating access to Chrome Login Data](tests/3d111226-d09a-4911-8715-fe11664f960d.md)
* posh_ps_accessing_win_api.yml
  * T1482 [Get-DomainTrust with PowerView](tests/f974894c-5991-4b19-aaf5-7cc2fe298c5d.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Rundll32 and Inline Protocol Handler](tests/e7e3a525-7612-4d68-a5d3-c4649181b8af.md)
  * T1134.004 [Parent PID Spoofing using PowerShell](tests/069258f4-2162-46e9-9a25-c9c6c56150d2.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement](tests/007e5672-2088-4853-a562-7490ddc19447.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations](tests/686a9785-f99b-41d4-90df-66ed515f81d7.md)
  * T1201 [Get-DomainPolicy with PowerView](tests/3177f4da-3d4b-4592-8bdc-aa23d0b2e843.md)
  * T1069.002 [Find Local Admins via Group Policy (PowerView)](tests/64fdb43b-5259-467a-b000-1b02c00e510a.md)
  * T1482 [Get-ForestTrust with PowerView](tests/58ed10e8-0738-4651-8408-3a3e9a526279.md)
  * T1069.002 [Find machines where user has local admin access (PowerView)](tests/a2d71eee-a353-4232-9f86-54f4288dd8c1.md)
  * T1033 [Find computers where user has session - Stealth mode (PowerView)](tests/29857f27-a36f-4f7e-8084-4557cd6207ca.md)
  * T1218.005 [Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine Simulating Double Click](tests/58a193ec-131b-404e-b1ca-b35cf0b18c33.md)
  * T1134.002 [Access Token Manipulation](tests/dbf4f5a9-b8e0-46a3-9841-9ad71247239e.md)
  * T1562.002 [Kill Event Log Service Threads](tests/41ac52ba-5d5e-40c0-b267-573ed90489bd.md)
  * T1491.001 [Replace Desktop Wallpaper](tests/30558d53-9d76-41c4-9267-a7bd5184bed3.md)
  * T1218.004 [InstallUtil Uninstall method call - /U variant](tests/34428cfa-8e38-41e5-aff4-9e1f8f3a7b4b.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1059.001 [PowerUp Invoke-AllChecks](tests/1289f78d-22d2-4590-ac76-166737e1811b.md)
  * T1558.003 [Request for service tickets](tests/3f987809-3681-43c8-bcd8-b3ff3a28533a.md)
  * T1218.004 [InstallUtil Install method call](tests/9f9968a6-601a-46ca-b7b7-6d4fe0f98f0b.md)
  * T1003.002 [PowerDump Hashes and Usernames from Registry](tests/804f28fc-68fc-40da-b5a2-e9d0bce5c193.md)
  * T1218.004 [InstallUtil Uninstall method call - '/installtype=notransaction /action=uninstall' variant](tests/06d9deba-f732-48a8-af8e-bdd6e4d98c1d.md)
  * T1557.001 [LLMNR Poisoning with Inveigh (PowerShell)](tests/deecd55f-afe0-4a62-9fba-4d1ba2deb321.md)
  * T1113 [Windows Screencapture](tests/3c898f62-626c-47d5-aad2-6de873d69153.md)
  * T1218 [Invoke-ATHRemoteFXvGPUDisablementCommand base test](tests/9ebe7901-7edf-45c0-b5c7-8366300919db.md)
  * T1218.004 [InstallUtil HelpText method call](tests/5a683850-1145-4326-a0e5-e91ced3c6022.md)
  * T1134.001 [Named pipe client impersonation](tests/90db9e27-8e7c-4c04-b602-a45927884966.md)
  * T1135 [Share Discovery with PowerView](tests/b1636f0a-ba82-435c-b699-0d78794d8bfd.md)
  * T1218.004 [InstallUtil evasive invocation](tests/559e6d06-bb42-4307-bff7-3b95a8254bad.md)
  * T1218.004 [CheckIfInstallable method call](tests/ffd9c807-d402-47d2-879d-f915cf2a3a94.md)
  * T1069.002 [Get-DomainGroupMember with PowerView](tests/46352f40-f283-4fe5-b56d-d9a71750e145.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations](tests/86a43bad-12e3-4e85-b97c-4d5cf25b95c3.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments](tests/0d181431-ddf3-4826-8055-2dbf63ae848b.md)
  * T1134.004 [Parent PID Spoofing - Spawn from New Process](tests/2988133e-561c-4e42-a15f-6281e6a9b2db.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Local](tests/78e95057-d429-4e66-8f82-0f060c1ac96f.md)
  * T1003.001 [Powershell Mimikatz](tests/66fb0bc1-3c3f-47e9-a298-550ecfefacbc.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Specified Process](tests/cbbff285-9051-444a-9d17-c07cd2d230eb.md)
  * T1218.004 [InstallHelper method call](tests/d43a5bde-ae28-4c55-a850-3f4c80573503.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Remote](tests/cab413d8-9e4a-4b8d-9b84-c985bd73a442.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
  * T1134.004 [Parent PID Spoofing - Spawn from svchost.exe](tests/e9f2b777-3123-430b-805d-5cedc66ab591.md)
  * T1134.001 [`SeDebugPrivilege` token duplication](tests/34f0a430-9d04-4d98-bcb5-1989f14719f0.md)
  * T1069.002 [Find local admins on all machines in domain (PowerView)](tests/a5f0d9f8-d3c9-46c0-8378-846ddd6b1cbd.md)
  * T1087.002 [Get-DomainUser with PowerView](tests/93662494-5ed7-4454-a04c-8c8372808ac2.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Current Process](tests/14920ebd-1d61-491a-85e0-fe98efe37f25.md)
  * T1218.004 [InstallUtil class constructor method call](tests/9b7a7cfc-dd2e-43f5-a885-c0a3c270dd93.md)
  * T1069.002 [Get-DomainGroup with PowerView](tests/5a8a181c-2c8e-478d-a943-549305a01230.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments](tests/1c0a870f-dc74-49cf-9afc-eccc45e58790.md)
  * T1055.012 [Process Hollowing using PowerShell](tests/562427b4-39ef-4e8c-af88-463a78e70b9c.md)
  * T1059.001 [Mimikatz](tests/f3132740-55bc-48c4-bcc0-758a459cd027.md)
  * T1003.001 [Dump LSASS.exe Memory using Out-Minidump.ps1](tests/6502c8f0-b775-4dbd-9193-1298f56b6781.md)
* posh_ps_adrecon_execution.yml
  * T1087.002 [Automated AD Recon (ADRecon)](tests/95018438-454a-468c-a0fa-59c800149b59.md)
* posh_ps_as_rep_roasting.yml
  * T1069.002 [Get-ADUser Enumeration using UserAccountControl flags (AS-REP Roasting)](tests/43fa81fb-34bb-4b5f-867b-03c7dbe0e3d8.md)
* posh_ps_automated_collection.yml
  * T1059.001 [PowerUp Invoke-AllChecks](tests/1289f78d-22d2-4590-ac76-166737e1811b.md)
  * T1119 [Automated Collection PowerShell](tests/634bd9b9-dc83-4229-b19f-7f83ba9ad313.md)
* posh_ps_capture_screenshots.yml
  * T1113 [Windows Screen Capture (CopyFromScreen)](tests/e9313014-985a-48ef-80d9-cde604ffc187.md)
* posh_ps_clearing_windows_console_history.yml
  * T1070.003 [Clear Powershell History by Deleting History File](tests/da75ae8d-26d6-4483-b0fe-700e4df4f037.md)
* posh_ps_cmdlet_scheduled_task.yml
  * T1053.005 [WMI Invoke-CimMethod Scheduled Task](tests/e16b3b75-dc9e-4cde-a23d-dfa2d0507b3b.md)
  * T1053.005 [Powershell Cmdlet Scheduled Task](tests/af9fd58f-c4ac-4bf2-a9ba-224b71ff25fd.md)
* posh_ps_copy_item_system32.yml
  * T1556.002 [Install and Register Password Filter DLL](tests/a7961770-beb5-4134-9674-83d7e1fa865c.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Rundll32 and Inline Protocol Handler](tests/e7e3a525-7612-4d68-a5d3-c4649181b8af.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement](tests/007e5672-2088-4853-a562-7490ddc19447.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations](tests/686a9785-f99b-41d4-90df-66ed515f81d7.md)
  * T1218.005 [Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine Simulating Double Click](tests/58a193ec-131b-404e-b1ca-b35cf0b18c33.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1218 [Invoke-ATHRemoteFXvGPUDisablementCommand base test](tests/9ebe7901-7edf-45c0-b5c7-8366300919db.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations](tests/86a43bad-12e3-4e85-b97c-4d5cf25b95c3.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments](tests/0d181431-ddf3-4826-8055-2dbf63ae848b.md)
  * T1134.004 [Parent PID Spoofing - Spawn from New Process](tests/2988133e-561c-4e42-a15f-6281e6a9b2db.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Specified Process](tests/cbbff285-9051-444a-9d17-c07cd2d230eb.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
  * T1134.004 [Parent PID Spoofing - Spawn from svchost.exe](tests/e9f2b777-3123-430b-805d-5cedc66ab591.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Current Process](tests/14920ebd-1d61-491a-85e0-fe98efe37f25.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments](tests/1c0a870f-dc74-49cf-9afc-eccc45e58790.md)
* posh_ps_cor_profiler.yml
  * T1574.012 [Registry-free process scope COR_PROFILER](tests/79d57242-bbef-41db-b301-9d01d9f6e817.md)
* posh_ps_create_local_user.yml
  * T1136.001 [Create a new user in PowerShell](tests/bc8be0ac-475c-4fbf-9b1d-9fffd77afbde.md)
  * T1564 [Create an "Administrator " user (with a space on the end)](tests/5bb20389-39a5-4e99-9264-aeb92a55a85c.md)
* posh_ps_create_volume_shadow_copy.yml
  * T1003.003 [Create Volume Shadow Copy with Powershell](tests/542bb97e-da53-436b-8e43-e0a7d31a6c24.md)
* posh_ps_data_compressed.yml
  * T1560 [Compress Data for Exfiltration With PowerShell](tests/41410c60-614d-4b9d-b66e-b0192dd9c597.md)
* posh_ps_detect_vm_env.yml
  * T1497.001 [Detect Virtualization Environment (Windows)](tests/502a7dc4-9d6f-4d28-abf2-f0e84692562d.md)
  * T1558.002 [Crafting Active Directory silver tickets with mimikatz](tests/385e59aa-113e-4711-84d9-f637aef01f2c.md)
  * T1497.001 [Detect Virtualization Environment via WMI Manufacturer/Model Listing (Windows)](tests/4a41089a-48e0-47aa-82cb-5b81a463bc78.md)
* posh_ps_directorysearcher.yml
  * T1018 [Enumerate domain computers within Active Directory using DirectorySearcher](tests/962a6017-1c09-45a6-880b-adc9c57cb22e.md)
* posh_ps_directoryservices_accountmanagement.yml
  * T1201 [Get-DomainPolicy with PowerView](tests/3177f4da-3d4b-4592-8bdc-aa23d0b2e843.md)
  * T1033 [Find computers where user has session - Stealth mode (PowerView)](tests/29857f27-a36f-4f7e-8084-4557cd6207ca.md)
  * T1136.002 [Create a new Domain Account using PowerShell](tests/5a3497a4-1568-4663-b12a-d4a5ed70c7d7.md)
  * T1069.002 [Get-DomainGroupMember with PowerView](tests/46352f40-f283-4fe5-b56d-d9a71750e145.md)
  * T1087.002 [Get-DomainUser with PowerView](tests/93662494-5ed7-4454-a04c-8c8372808ac2.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
  * T1069.002 [Get-DomainGroup with PowerView](tests/5a8a181c-2c8e-478d-a943-549305a01230.md)
* posh_ps_dnscat_execution.yml
  * T1071.004 [DNS C2](tests/e7bf9802-2e78-4db9-93b5-181b7bcd37d7.md)
* posh_ps_dump_password_windows_credential_manager.yml
  * T1555 [Dump credentials from Windows Credential Manager With PowerShell [web Credentials]](tests/8fd5a296-6772-4766-9991-ff4e92af7240.md)
  * T1555 [Dump credentials from Windows Credential Manager With PowerShell [windows Credentials]](tests/c89becbe-1758-4e7d-a0f4-97d2188a23e3.md)
* posh_ps_enable_psremoting.yml
  * T1021.006 [Enable Windows Remote Management](tests/9059e8de-3d7d-4954-a322-46161880b9cf.md)
* posh_ps_enumerate_password_windows_credential_manager.yml
  * T1555 [Enumerate credentials from Windows Credential Manager using vaultcmd.exe [Windows Credentials]](tests/36753ded-e5c4-4eb5-bc3c-e8fba236878d.md)
  * T1555 [Enumerate credentials from Windows Credential Manager using vaultcmd.exe [Web Credentials]](tests/bc071188-459f-44d5-901a-f8f2625b2d2e.md)
* posh_ps_file_and_directory_discovery.yml
  * T1218.005 [Invoke HTML Application - JScript Engine with Rundll32 and Inline Protocol Handler](tests/e7e3a525-7612-4d68-a5d3-c4649181b8af.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement](tests/007e5672-2088-4853-a562-7490ddc19447.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations](tests/686a9785-f99b-41d4-90df-66ed515f81d7.md)
  * T1021.006 [Enable Windows Remote Management](tests/9059e8de-3d7d-4954-a322-46161880b9cf.md)
  * T1201 [Get-DomainPolicy with PowerView](tests/3177f4da-3d4b-4592-8bdc-aa23d0b2e843.md)
  * T1033 [Find computers where user has session - Stealth mode (PowerView)](tests/29857f27-a36f-4f7e-8084-4557cd6207ca.md)
  * T1218.005 [Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine Simulating Double Click](tests/58a193ec-131b-404e-b1ca-b35cf0b18c33.md)
  * T1083 [File and Directory Discovery (PowerShell)](tests/2158908e-b7ef-4c21-8a83-3ce4dd05a924.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1059.001 [Invoke-AppPathBypass](tests/06a220b6-7e29-4bd8-9d07-5b4d86742372.md)
  * T1059.001 [PowerUp Invoke-AllChecks](tests/1289f78d-22d2-4590-ac76-166737e1811b.md)
  * T1218 [Invoke-ATHRemoteFXvGPUDisablementCommand base test](tests/9ebe7901-7edf-45c0-b5c7-8366300919db.md)
  * T1069.002 [Get-DomainGroupMember with PowerView](tests/46352f40-f283-4fe5-b56d-d9a71750e145.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations](tests/86a43bad-12e3-4e85-b97c-4d5cf25b95c3.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments](tests/0d181431-ddf3-4826-8055-2dbf63ae848b.md)
  * T1134.004 [Parent PID Spoofing - Spawn from New Process](tests/2988133e-561c-4e42-a15f-6281e6a9b2db.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Specified Process](tests/cbbff285-9051-444a-9d17-c07cd2d230eb.md)
  * T1562.001 [Uninstall Crowdstrike Falcon on Windows](tests/b32b1ccf-f7c1-49bc-9ddd-7d7466a7b297.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
  * T1134.004 [Parent PID Spoofing - Spawn from svchost.exe](tests/e9f2b777-3123-430b-805d-5cedc66ab591.md)
  * T1087.002 [Get-DomainUser with PowerView](tests/93662494-5ed7-4454-a04c-8c8372808ac2.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Current Process](tests/14920ebd-1d61-491a-85e0-fe98efe37f25.md)
  * T1069.002 [Get-DomainGroup with PowerView](tests/5a8a181c-2c8e-478d-a943-549305a01230.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments](tests/1c0a870f-dc74-49cf-9afc-eccc45e58790.md)
* posh_ps_get_acl_service.yml
  * T1574.011 [Service Registry Permissions Weakness](tests/f7536d63-7fd4-466f-89da-7e48d550752a.md)
* posh_ps_get_adreplaccount.yml
  * T1003.006 [Run DSInternals Get-ADReplAccount](tests/a0bced08-3fc5-4d8b-93b7-e8344739376e.md)
* posh_ps_get_childitem_bookmarks.yml
  * T1217 [List Google Chrome / Opera Bookmarks on Windows with powershell](tests/faab755e-4299-48ec-8202-fc7885eb6545.md)
* posh_ps_icmp_exfiltration.yml
  * T1095 [ICMP C2](tests/0268e63c-e244-42db-bef7-72a9e59fc1fc.md)
  * T1048.003 [Exfiltration Over Alternative Protocol - ICMP](tests/dd4b4421-2e25-4593-90ae-7021947ad12e.md)
* posh_ps_invoke_command_remote.yml
  * T1201 [Get-DomainPolicy with PowerView](tests/3177f4da-3d4b-4592-8bdc-aa23d0b2e843.md)
  * T1562.002 [Kill Event Log Service Threads](tests/41ac52ba-5d5e-40c0-b267-573ed90489bd.md)
  * T1021.006 [Invoke-Command](tests/5295bd61-bd7e-4744-9d52-85962a4cf2d6.md)
  * T1069.002 [Get-DomainGroupMember with PowerView](tests/46352f40-f283-4fe5-b56d-d9a71750e145.md)
  * T1087.002 [Get-DomainUser with PowerView](tests/93662494-5ed7-4454-a04c-8c8372808ac2.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
  * T1069.002 [Get-DomainGroup with PowerView](tests/5a8a181c-2c8e-478d-a943-549305a01230.md)
* posh_ps_invoke_dnsexfiltration.yml
  * T1048 [DNSExfiltration (doh)](tests/c943d285-ada3-45ca-b3aa-7cd6500c6a48.md)
* posh_ps_keylogging.yml
  * T1059.001 [PowerShell Invoke Known Malicious Cmdlets](tests/49eb9404-5e0f-4031-a179-b40f7be385e3.md)
  * T1056.001 [Input Capture](tests/d9b633ca-8efb-45e6-b838-70f595c6ae26.md)
* posh_ps_localuser.yml
  * T1098 [Admin Account Manipulate](tests/5598f7cb-cf43-455e-883a-f6008c5d46af.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Local](tests/78e95057-d429-4e66-8f82-0f060c1ac96f.md)
  * T1564 [Create an "Administrator " user (with a space on the end)](tests/5bb20389-39a5-4e99-9264-aeb92a55a85c.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Remote](tests/cab413d8-9e4a-4b8d-9b84-c985bd73a442.md)
  * T1218.005 [Mshta executes VBScript to execute malicious command](tests/906865c3-e05f-4acc-85c4-fbc185455095.md)
* posh_ps_malicious_commandlets.yml
  * T1059.001 [PowerShell Invoke Known Malicious Cmdlets](tests/49eb9404-5e0f-4031-a179-b40f7be385e3.md)
  * T1003.006 [Run DSInternals Get-ADReplAccount](tests/a0bced08-3fc5-4d8b-93b7-e8344739376e.md)
  * T1201 [Get-DomainPolicy with PowerView](tests/3177f4da-3d4b-4592-8bdc-aa23d0b2e843.md)
  * T1033 [Find computers where user has session - Stealth mode (PowerView)](tests/29857f27-a36f-4f7e-8084-4557cd6207ca.md)
  * T1562.002 [Kill Event Log Service Threads](tests/41ac52ba-5d5e-40c0-b267-573ed90489bd.md)
  * T1552.006 [GPP Passwords (Get-GPPPassword)](tests/e9584f82-322c-474a-b831-940fd8b4455c.md)
  * T1059.001 [PowerUp Invoke-AllChecks](tests/1289f78d-22d2-4590-ac76-166737e1811b.md)
  * T1558.003 [Request for service tickets](tests/3f987809-3681-43c8-bcd8-b3ff3a28533a.md)
  * T1003.002 [PowerDump Hashes and Usernames from Registry](tests/804f28fc-68fc-40da-b5a2-e9d0bce5c193.md)
  * T1557.001 [LLMNR Poisoning with Inveigh (PowerShell)](tests/deecd55f-afe0-4a62-9fba-4d1ba2deb321.md)
  * T1134.001 [Named pipe client impersonation](tests/90db9e27-8e7c-4c04-b602-a45927884966.md)
  * T1069.002 [Get-DomainGroupMember with PowerView](tests/46352f40-f283-4fe5-b56d-d9a71750e145.md)
  * T1615 [Get-DomainGPO to display group policy information via PowerView](tests/4e524c4e-0e02-49aa-8df5-93f3f7959b9f.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Local](tests/78e95057-d429-4e66-8f82-0f060c1ac96f.md)
  * T1003.001 [Powershell Mimikatz](tests/66fb0bc1-3c3f-47e9-a298-550ecfefacbc.md)
  * T1135 [PowerView ShareFinder](tests/d07e4cc1-98ae-447e-9d31-36cb430d28c4.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Remote](tests/cab413d8-9e4a-4b8d-9b84-c985bd73a442.md)
  * T1134.001 [`SeDebugPrivilege` token duplication](tests/34f0a430-9d04-4d98-bcb5-1989f14719f0.md)
  * T1087.002 [Get-DomainUser with PowerView](tests/93662494-5ed7-4454-a04c-8c8372808ac2.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
  * T1059.001 [Obfuscation Tests](tests/4297c41a-8168-4138-972d-01f3ee92c804.md)
  * T1069.002 [Get-DomainGroup with PowerView](tests/5a8a181c-2c8e-478d-a943-549305a01230.md)
  * T1059.001 [Mimikatz - Cradlecraft PsSendKeys](tests/af1800cf-9f9d-4fd1-a709-14b1e6de020d.md)
  * T1059.001 [Mimikatz](tests/f3132740-55bc-48c4-bcc0-758a459cd027.md)
  * T1003.001 [Dump LSASS.exe Memory using Out-Minidump.ps1](tests/6502c8f0-b775-4dbd-9193-1298f56b6781.md)
* posh_ps_malicious_keywords.yml
  * T1482 [Get-DomainTrust with PowerView](tests/f974894c-5991-4b19-aaf5-7cc2fe298c5d.md)
  * T1207 [DCShadow (Active Directory)](tests/0f4c5eb0-98a0-4496-9c3d-656b4f2bc8f6.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Rundll32 and Inline Protocol Handler](tests/e7e3a525-7612-4d68-a5d3-c4649181b8af.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement](tests/007e5672-2088-4853-a562-7490ddc19447.md)
  * T1059.001 [PowerShell Invoke Known Malicious Cmdlets](tests/49eb9404-5e0f-4031-a179-b40f7be385e3.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations](tests/686a9785-f99b-41d4-90df-66ed515f81d7.md)
  * T1201 [Get-DomainPolicy with PowerView](tests/3177f4da-3d4b-4592-8bdc-aa23d0b2e843.md)
  * T1069.002 [Find Local Admins via Group Policy (PowerView)](tests/64fdb43b-5259-467a-b000-1b02c00e510a.md)
  * T1482 [Get-ForestTrust with PowerView](tests/58ed10e8-0738-4651-8408-3a3e9a526279.md)
  * T1069.002 [Find machines where user has local admin access (PowerView)](tests/a2d71eee-a353-4232-9f86-54f4288dd8c1.md)
  * T1033 [Find computers where user has session - Stealth mode (PowerView)](tests/29857f27-a36f-4f7e-8084-4557cd6207ca.md)
  * T1218.005 [Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine Simulating Double Click](tests/58a193ec-131b-404e-b1ca-b35cf0b18c33.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1059.001 [PowerUp Invoke-AllChecks](tests/1289f78d-22d2-4590-ac76-166737e1811b.md)
  * T1003.002 [PowerDump Hashes and Usernames from Registry](tests/804f28fc-68fc-40da-b5a2-e9d0bce5c193.md)
  * T1557.001 [LLMNR Poisoning with Inveigh (PowerShell)](tests/deecd55f-afe0-4a62-9fba-4d1ba2deb321.md)
  * T1218 [Invoke-ATHRemoteFXvGPUDisablementCommand base test](tests/9ebe7901-7edf-45c0-b5c7-8366300919db.md)
  * T1558.002 [Crafting Active Directory silver tickets with mimikatz](tests/385e59aa-113e-4711-84d9-f637aef01f2c.md)
  * T1134.001 [Named pipe client impersonation](tests/90db9e27-8e7c-4c04-b602-a45927884966.md)
  * T1135 [Share Discovery with PowerView](tests/b1636f0a-ba82-435c-b699-0d78794d8bfd.md)
  * T1069.002 [Get-DomainGroupMember with PowerView](tests/46352f40-f283-4fe5-b56d-d9a71750e145.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations](tests/86a43bad-12e3-4e85-b97c-4d5cf25b95c3.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments](tests/0d181431-ddf3-4826-8055-2dbf63ae848b.md)
  * T1134.004 [Parent PID Spoofing - Spawn from New Process](tests/2988133e-561c-4e42-a15f-6281e6a9b2db.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Local](tests/78e95057-d429-4e66-8f82-0f060c1ac96f.md)
  * T1003.001 [Powershell Mimikatz](tests/66fb0bc1-3c3f-47e9-a298-550ecfefacbc.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Specified Process](tests/cbbff285-9051-444a-9d17-c07cd2d230eb.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
  * T1558.001 [Crafting Active Directory golden tickets with mimikatz](tests/9726592a-dabc-4d4d-81cd-44070008b3af.md)
  * T1134.004 [Parent PID Spoofing - Spawn from svchost.exe](tests/e9f2b777-3123-430b-805d-5cedc66ab591.md)
  * T1134.001 [`SeDebugPrivilege` token duplication](tests/34f0a430-9d04-4d98-bcb5-1989f14719f0.md)
  * T1069.002 [Find local admins on all machines in domain (PowerView)](tests/a5f0d9f8-d3c9-46c0-8378-846ddd6b1cbd.md)
  * T1087.002 [Get-DomainUser with PowerView](tests/93662494-5ed7-4454-a04c-8c8372808ac2.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
  * T1059.001 [Obfuscation Tests](tests/4297c41a-8168-4138-972d-01f3ee92c804.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Current Process](tests/14920ebd-1d61-491a-85e0-fe98efe37f25.md)
  * T1069.002 [Get-DomainGroup with PowerView](tests/5a8a181c-2c8e-478d-a943-549305a01230.md)
  * T1059.001 [Mimikatz - Cradlecraft PsSendKeys](tests/af1800cf-9f9d-4fd1-a709-14b1e6de020d.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments](tests/1c0a870f-dc74-49cf-9afc-eccc45e58790.md)
  * T1055.012 [Process Hollowing using PowerShell](tests/562427b4-39ef-4e8c-af88-463a78e70b9c.md)
  * T1059.001 [Mimikatz](tests/f3132740-55bc-48c4-bcc0-758a459cd027.md)
  * T1003.001 [Dump LSASS.exe Memory using Out-Minidump.ps1](tests/6502c8f0-b775-4dbd-9193-1298f56b6781.md)
* posh_ps_msxml_com.yml
  * T1059.001 [Powershell MsXml COM object - with prompt](tests/388a7340-dbc1-4c9d-8e59-b75ad8c6d5da.md)
* posh_ps_nishang_malicious_commandlets.yml
  * T1095 [ICMP C2](tests/0268e63c-e244-42db-bef7-72a9e59fc1fc.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Local](tests/78e95057-d429-4e66-8f82-0f060c1ac96f.md)
  * T1003.001 [Powershell Mimikatz](tests/66fb0bc1-3c3f-47e9-a298-550ecfefacbc.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Remote](tests/cab413d8-9e4a-4b8d-9b84-c985bd73a442.md)
  * T1056.001 [Input Capture](tests/d9b633ca-8efb-45e6-b838-70f595c6ae26.md)
  * T1059.001 [Obfuscation Tests](tests/4297c41a-8168-4138-972d-01f3ee92c804.md)
  * T1059.001 [Mimikatz](tests/f3132740-55bc-48c4-bcc0-758a459cd027.md)
* posh_ps_ntfs_ads_access.yml
  * T1059.001 [NTFS Alternate Data Stream Access](tests/8e5c5532-1181-4c1d-bb79-b3a9f5dbd680.md)
  * T1564.004 [Create ADS PowerShell](tests/0045ea16-ed3c-4d4c-a9ee-15e44d1560d1.md)
* posh_ps_office_comobject_registerxll.yml
  * T1137.006 [Code Executed Via Excel Add-in File (Xll)](tests/441b1a0f-a771-428a-8af0-e99e4698cda3.md)
* posh_ps_powerview_malicious_commandlets.yml
  * T1201 [Get-DomainPolicy with PowerView](tests/3177f4da-3d4b-4592-8bdc-aa23d0b2e843.md)
  * T1033 [Find computers where user has session - Stealth mode (PowerView)](tests/29857f27-a36f-4f7e-8084-4557cd6207ca.md)
  * T1558.003 [Request for service tickets](tests/3f987809-3681-43c8-bcd8-b3ff3a28533a.md)
  * T1110.003 [Password Spray (DomainPasswordSpray)](tests/263ae743-515f-4786-ac7d-41ef3a0d4b2b.md)
  * T1069.002 [Get-DomainGroupMember with PowerView](tests/46352f40-f283-4fe5-b56d-d9a71750e145.md)
  * T1615 [Get-DomainGPO to display group policy information via PowerView](tests/4e524c4e-0e02-49aa-8df5-93f3f7959b9f.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Local](tests/78e95057-d429-4e66-8f82-0f060c1ac96f.md)
  * T1135 [PowerView ShareFinder](tests/d07e4cc1-98ae-447e-9d31-36cb430d28c4.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Remote](tests/cab413d8-9e4a-4b8d-9b84-c985bd73a442.md)
  * T1087.002 [Enumerate Active Directory for Unconstrained Delegation](tests/46f8dbe9-22a5-4770-8513-66119c5be63b.md)
  * T1482 [Powershell enumerate domains and forests](tests/c58fbc62-8a62-489e-8f2d-3565d7d96f30.md)
  * T1087.002 [Get-DomainUser with PowerView](tests/93662494-5ed7-4454-a04c-8c8372808ac2.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
  * T1069.002 [Get-DomainGroup with PowerView](tests/5a8a181c-2c8e-478d-a943-549305a01230.md)
* posh_ps_prompt_credentials.yml
  * T1056.002 [PowerShell - Prompt User for Password](tests/2b162bfd-0928-4d4c-9ec3-4d9f88374b52.md)
* posh_ps_remote_session_creation.yml
  * T1059.001 [PowerShell Session Creation and Use](tests/7c1acec2-78fa-4305-a3e0-db2a54cddecd.md)
* posh_ps_remove_item_path.yml
  * T1021.006 [Enable Windows Remote Management](tests/9059e8de-3d7d-4954-a322-46161880b9cf.md)
  * T1204.002 [Office Generic Payload Download](tests/5202ee05-c420-4148-bf5e-fd7f7d24850c.md)
  * T1059.001 [Invoke-AppPathBypass](tests/06a220b6-7e29-4bd8-9d07-5b4d86742372.md)
  * T1218 [Invoke-ATHRemoteFXvGPUDisablementCommand base test](tests/9ebe7901-7edf-45c0-b5c7-8366300919db.md)
  * T1558.002 [Crafting Active Directory silver tickets with mimikatz](tests/385e59aa-113e-4711-84d9-f637aef01f2c.md)
  * T1070.004 [Delete Prefetch File](tests/36f96049-0ad7-4a5f-8418-460acaeb92fb.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Local](tests/78e95057-d429-4e66-8f82-0f060c1ac96f.md)
  * T1562.001 [AMSI Bypass - Remove AMSI Provider Reg Key](tests/13f09b91-c953-438e-845b-b585e51cac9b.md)
  * T1070.004 [Delete a single file - Windows PowerShell](tests/9dee89bd-9a98-4c4f-9e2d-4256690b0e72.md)
  * T1059.001 [PowerShell Session Creation and Use](tests/7c1acec2-78fa-4305-a3e0-db2a54cddecd.md)
  * T1070.004 [Delete an entire folder - Windows PowerShell](tests/edd779e4-a509-4cba-8dfa-a112543dbfb1.md)
* posh_ps_request_kerberos_ticket.yml
  * T1201 [Get-DomainPolicy with PowerView](tests/3177f4da-3d4b-4592-8bdc-aa23d0b2e843.md)
  * T1033 [Find computers where user has session - Stealth mode (PowerView)](tests/29857f27-a36f-4f7e-8084-4557cd6207ca.md)
  * T1558.003 [Request A Single Ticket via PowerShell](tests/988539bc-2ed7-4e62-aec6-7c5cf6680863.md)
  * T1069.002 [Get-DomainGroupMember with PowerView](tests/46352f40-f283-4fe5-b56d-d9a71750e145.md)
  * T1087.002 [Get-DomainUser with PowerView](tests/93662494-5ed7-4454-a04c-8c8372808ac2.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
  * T1069.002 [Get-DomainGroup with PowerView](tests/5a8a181c-2c8e-478d-a943-549305a01230.md)
* posh_ps_root_certificate_installed.yml
  * T1553.004 [Install root CA on Windows](tests/76f49d86-5eb1-461a-a032-a480f86652f1.md)
* posh_ps_run_from_mount_diskimage.yml
  * T1553.005 [Mount an ISO image and run executable from the ISO](tests/42f22b00-0242-4afc-a61b-0da05041f9cc.md)
* posh_ps_security_software_discovery.yml
  * T1518.001 [Security Software Discovery - powershell](tests/7f566051-f033-49fb-89de-b6bacab730f0.md)
* posh_ps_send_mailmessage.yml
  * T1027 [DLP Evasion via Sensitive Data in VBA Macro over email](tests/129edb75-d7b8-42cd-a8ba-1f3db64ec4ad.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Local](tests/78e95057-d429-4e66-8f82-0f060c1ac96f.md)
  * T1048.003 [Exfiltration Over Alternative Protocol - SMTP](tests/ec3a835e-adca-4c7c-88d2-853b69c11bb9.md)
* posh_ps_set_policies_to_unsecure_level.yml
  * T1134.002 [Access Token Manipulation](tests/dbf4f5a9-b8e0-46a3-9841-9ad71247239e.md)
  * T1003.002 [PowerDump Hashes and Usernames from Registry](tests/804f28fc-68fc-40da-b5a2-e9d0bce5c193.md)
  * T1112 [Change Powershell Execution Policy to Bypass](tests/f3a6cceb-06c9-48e5-8df8-8867a6814245.md)
* posh_ps_shellintel_malicious_commandlets.yml
  * T1059.001 [PowerShell Invoke Known Malicious Cmdlets](tests/49eb9404-5e0f-4031-a179-b40f7be385e3.md)
  * T1003.001 [Dump LSASS.exe Memory using Out-Minidump.ps1](tests/6502c8f0-b775-4dbd-9193-1298f56b6781.md)
* posh_ps_software_discovery.yml
  * T1518 [Applications Installed](tests/c49978f6-bd6e-4221-ad2c-9e3e30cc1e3b.md)
* posh_ps_store_file_in_alternate_data_stream.yml
  * T1564.004 [Store file in Alternate Data Stream (ADS)](tests/2ab75061-f5d5-4c1a-b666-ba2a50df5b02.md)
* posh_ps_susp_directory_enum.yml
  * T1083 [Simulating MAZE Directory Enumeration](tests/c6c34f61-1c3e-40fb-8a58-d017d88286d8.md)
* posh_ps_susp_get_adcomputer.yml
  * T1018 [Enumerate Active Directory Computers with Get-AdComputer](tests/97e89d9e-e3f5-41b5-a90f-1e0825df0fdf.md)
* posh_ps_susp_get_addefaultdomainpasswordpolicy.yml
  * T1201 [Enumerate Active Directory Password Policy with get-addefaultdomainpasswordpolicy](tests/b2698b33-984c-4a1c-93bb-e4ba72a0babb.md)
* posh_ps_susp_get_adgroup.yml
  * T1069.002 [Enumerate Active Directory Groups with Get-AdGroup](tests/3d1fcd2a-e51c-4cbe-8d84-9a843bad8dc8.md)
* posh_ps_susp_invoke_webrequest_useragent.yml
  * T1071.001 [Malicious User Agents - Powershell](tests/81c13829-f6c9-45b8-85a6-053366d55297.md)
* posh_ps_susp_remove_adgroupmember.yml
  * T1531 [Remove Account From Domain Admin Group](tests/43f71395-6c37-498e-ab17-897d814a0947.md)
* posh_ps_susp_wallpaper.yml
  * T1491.001 [Replace Desktop Wallpaper](tests/30558d53-9d76-41c4-9267-a7bd5184bed3.md)
* posh_ps_susp_win32_shadowcopy.yml
  * T1489 [Windows - Stop service by killing process](tests/f3191b84-c38b-400b-867e-3a217a27795f.md)
  * T1490 [Windows - Delete Volume Shadow Copies via WMI with PowerShell](tests/39a295ca-7059-4a88-86f6-09556c1211e7.md)
* posh_ps_susp_zip_compress.yml
  * T1074.001 [Zip a Folder with PowerShell for Staging in Temp](tests/a57fbe4b-3440-452a-88a7-943531ac872a.md)
* posh_ps_suspicious_ad_group_reco.yml
  * T1069.002 [Enumerate Users Not Requiring Pre Auth (ASRepRoast)](tests/870ba71e-6858-4f6d-895c-bb6237f6121b.md)
  * T1069.002 [Permission Groups Discovery PowerShell (Domain)](tests/6d5d8c96-3d2a-4da9-9d6d-9a9d341899a7.md)
* posh_ps_suspicious_download.yml
  * T1105 [Windows - PowerShell Download](tests/42dc4460-9aa6-45d3-b1a6-3955d34e1fe8.md)
  * T1095 [Powercat C2](tests/3e0e0e7f-6aa2-4a61-b61d-526c2cc9330e.md)
  * T1095 [ICMP C2](tests/0268e63c-e244-42db-bef7-72a9e59fc1fc.md)
  * T1071.004 [DNS C2](tests/e7bf9802-2e78-4db9-93b5-181b7bcd37d7.md)
* posh_ps_suspicious_execute_batch_script.yml
  * T1059.003 [Create and Execute Batch Script](tests/9e8894c0-50bd-4525-a96c-d4ac78ece388.md)
* posh_ps_suspicious_export_pfxcertificate.yml
  * T1552.004 [ADFS token signing and encryption certificates theft - Local](tests/78e95057-d429-4e66-8f82-0f060c1ac96f.md)
* posh_ps_suspicious_extracting.yml
  * T1552.001 [Extracting passwords with findstr](tests/0e56bf29-ff49-4ea5-9af4-3b81283fd513.md)
  * T1069.002 [Get-DomainGroup with PowerView](tests/5a8a181c-2c8e-478d-a943-549305a01230.md)
* posh_ps_suspicious_get_current_user.yml
  * T1033 [User Discovery With Env Vars PowerShell Script](tests/dcb6cdee-1fb0-4087-8bf8-88cfd136ba51.md)
  * T1033 [GetCurrent User with PowerShell Script](tests/1392bd0f-5d5a-429e-81d9-eb9d4d4d5b3b.md)
* posh_ps_suspicious_getprocess_lsass.yml
  * T1134.002 [Access Token Manipulation](tests/dbf4f5a9-b8e0-46a3-9841-9ad71247239e.md)
  * T1003.001 [Dump LSASS.exe Memory using comsvcs.dll](tests/2536dee2-12fb-459a-8c37-971844fa73be.md)
  * T1003.001 [Dump LSASS.exe Memory using Out-Minidump.ps1](tests/6502c8f0-b775-4dbd-9193-1298f56b6781.md)
* posh_ps_suspicious_gettypefromclsid.yml
  * T1546.015 [Powershell Execute COM Object](tests/752191b1-7c71-445c-9dbe-21bb031b18eb.md)
* posh_ps_suspicious_gwmi.yml
  * T1218.005 [Invoke HTML Application - JScript Engine with Rundll32 and Inline Protocol Handler](tests/e7e3a525-7612-4d68-a5d3-c4649181b8af.md)
  * T1057 [Process Discovery - get-wmiObject](tests/b51239b4-0129-474f-a2b4-70f855b9f2c2.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement](tests/007e5672-2088-4853-a562-7490ddc19447.md)
  * T1018 [Get-wmiobject to Enumerate Domain Controllers](tests/e3cf5123-f6c9-4375-bdf2-1bb3ba43a1ad.md)
  * T1201 [Get-DomainPolicy with PowerView](tests/3177f4da-3d4b-4592-8bdc-aa23d0b2e843.md)
  * T1218.005 [Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine Simulating Double Click](tests/58a193ec-131b-404e-b1ca-b35cf0b18c33.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1003.003 [Create Volume Shadow Copy with Powershell](tests/542bb97e-da53-436b-8e43-e0a7d31a6c24.md)
  * T1218 [Invoke-ATHRemoteFXvGPUDisablementCommand base test](tests/9ebe7901-7edf-45c0-b5c7-8366300919db.md)
  * T1558.002 [Crafting Active Directory silver tickets with mimikatz](tests/385e59aa-113e-4711-84d9-f637aef01f2c.md)
  * T1057 [Process Discovery - Get-Process](tests/3b3809b6-a54b-4f5b-8aff-cb51f2e97b34.md)
  * T1134.001 [Named pipe client impersonation](tests/90db9e27-8e7c-4c04-b602-a45927884966.md)
  * T1497.001 [Detect Virtualization Environment via WMI Manufacturer/Model Listing (Windows)](tests/4a41089a-48e0-47aa-82cb-5b81a463bc78.md)
  * T1069.002 [Get-DomainGroupMember with PowerView](tests/46352f40-f283-4fe5-b56d-d9a71750e145.md)
  * T1134.004 [Parent PID Spoofing - Spawn from New Process](tests/2988133e-561c-4e42-a15f-6281e6a9b2db.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Local](tests/78e95057-d429-4e66-8f82-0f060c1ac96f.md)
  * T1091 [USB Malware Spread Simulation](tests/d44b7297-622c-4be8-ad88-ec40d7563c75.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Specified Process](tests/cbbff285-9051-444a-9d17-c07cd2d230eb.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
  * T1134.004 [Parent PID Spoofing - Spawn from svchost.exe](tests/e9f2b777-3123-430b-805d-5cedc66ab591.md)
  * T1134.001 [`SeDebugPrivilege` token duplication](tests/34f0a430-9d04-4d98-bcb5-1989f14719f0.md)
  * T1087.002 [Get-DomainUser with PowerView](tests/93662494-5ed7-4454-a04c-8c8372808ac2.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Current Process](tests/14920ebd-1d61-491a-85e0-fe98efe37f25.md)
  * T1069.002 [Get-DomainGroup with PowerView](tests/5a8a181c-2c8e-478d-a943-549305a01230.md)
* posh_ps_suspicious_hyper_v_condlet.yml
  * T1564.006 [Create and start Hyper-V virtual machine](tests/fb8d4d7e-f5a4-481c-8867-febf13f8b6d3.md)
* posh_ps_suspicious_invocation_specific.yml
  * T1095 [Powercat C2](tests/3e0e0e7f-6aa2-4a61-b61d-526c2cc9330e.md)
  * T1059.001 [Run Bloodhound from Memory using Download Cradle](tests/bf8c1441-4674-4dab-8e4e-39d93d08f9b7.md)
  * T1095 [ICMP C2](tests/0268e63c-e244-42db-bef7-72a9e59fc1fc.md)
  * T1071.004 [DNS C2](tests/e7bf9802-2e78-4db9-93b5-181b7bcd37d7.md)
  * T1059.001 [Invoke-AppPathBypass](tests/06a220b6-7e29-4bd8-9d07-5b4d86742372.md)
  * T1615 [Get-DomainGPO to display group policy information via PowerView](tests/4e524c4e-0e02-49aa-8df5-93f3f7959b9f.md)
  * T1547.001 [PowerShell Registry RunOnce](tests/eb44f842-0457-4ddc-9b92-c4caa144ac42.md)
  * T1059.001 [Obfuscation Tests](tests/4297c41a-8168-4138-972d-01f3ee92c804.md)
  * T1059.001 [Mimikatz](tests/f3132740-55bc-48c4-bcc0-758a459cd027.md)
  * T1003.001 [Dump LSASS.exe Memory using Out-Minidump.ps1](tests/6502c8f0-b775-4dbd-9193-1298f56b6781.md)
* posh_ps_suspicious_iofilestream.yml
  * T1006 [Read volume boot sector via DOS device path (PowerShell)](tests/88f6327e-51ec-4bbf-b2e8-3fea534eab8b.md)
* posh_ps_suspicious_keywords.yml
  * T1218.005 [Invoke HTML Application - JScript Engine with Rundll32 and Inline Protocol Handler](tests/e7e3a525-7612-4d68-a5d3-c4649181b8af.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement](tests/007e5672-2088-4853-a562-7490ddc19447.md)
  * T1059.001 [Run Bloodhound from Memory using Download Cradle](tests/bf8c1441-4674-4dab-8e4e-39d93d08f9b7.md)
  * T1059.001 [Run BloodHound from local disk](tests/a21bb23e-e677-4ee7-af90-6931b57b6350.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations](tests/686a9785-f99b-41d4-90df-66ed515f81d7.md)
  * T1201 [Get-DomainPolicy with PowerView](tests/3177f4da-3d4b-4592-8bdc-aa23d0b2e843.md)
  * T1033 [Find computers where user has session - Stealth mode (PowerView)](tests/29857f27-a36f-4f7e-8084-4557cd6207ca.md)
  * T1218.005 [Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine Simulating Double Click](tests/58a193ec-131b-404e-b1ca-b35cf0b18c33.md)
  * T1562.002 [Kill Event Log Service Threads](tests/41ac52ba-5d5e-40c0-b267-573ed90489bd.md)
  * T1071.004 [DNS C2](tests/e7bf9802-2e78-4db9-93b5-181b7bcd37d7.md)
  * T1047 [Create a Process using obfuscated Win32_Process](tests/10447c83-fc38-462a-a936-5102363b1c43.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1048.003 [Exfiltration Over Alternative Protocol - HTTP](tests/6aa58451-1121-4490-a8e9-1dada3f1c68c.md)
  * T1059.001 [PowerUp Invoke-AllChecks](tests/1289f78d-22d2-4590-ac76-166737e1811b.md)
  * T1003.001 [Dump LSASS.exe Memory using comsvcs.dll](tests/2536dee2-12fb-459a-8c37-971844fa73be.md)
  * T1218.011 [Execution of non-dll using rundll32.exe](tests/ae3a8605-b26e-457c-b6b3-2702fd335bac.md)
  * T1218 [Invoke-ATHRemoteFXvGPUDisablementCommand base test](tests/9ebe7901-7edf-45c0-b5c7-8366300919db.md)
  * T1047 [Create a Process using WMI Query and an Encoded Command](tests/7db7a7f9-9531-4840-9b30-46220135441c.md)
  * T1134.001 [Named pipe client impersonation](tests/90db9e27-8e7c-4c04-b602-a45927884966.md)
  * T1069.002 [Get-DomainGroupMember with PowerView](tests/46352f40-f283-4fe5-b56d-d9a71750e145.md)
  * T1003 [Dump svchost.exe to gather RDP credentials](tests/d400090a-d8ca-4be0-982e-c70598a23de9.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations](tests/86a43bad-12e3-4e85-b97c-4d5cf25b95c3.md)
  * T1048 [DNSExfiltration (doh)](tests/c943d285-ada3-45ca-b3aa-7cd6500c6a48.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments](tests/0d181431-ddf3-4826-8055-2dbf63ae848b.md)
  * T1134.004 [Parent PID Spoofing - Spawn from New Process](tests/2988133e-561c-4e42-a15f-6281e6a9b2db.md)
  * T1003.001 [Powershell Mimikatz](tests/66fb0bc1-3c3f-47e9-a298-550ecfefacbc.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Specified Process](tests/cbbff285-9051-444a-9d17-c07cd2d230eb.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
  * T1134.004 [Parent PID Spoofing - Spawn from svchost.exe](tests/e9f2b777-3123-430b-805d-5cedc66ab591.md)
  * T1134.001 [`SeDebugPrivilege` token duplication](tests/34f0a430-9d04-4d98-bcb5-1989f14719f0.md)
  * T1087.002 [Get-DomainUser with PowerView](tests/93662494-5ed7-4454-a04c-8c8372808ac2.md)
  * T1056.001 [Input Capture](tests/d9b633ca-8efb-45e6-b838-70f595c6ae26.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Current Process](tests/14920ebd-1d61-491a-85e0-fe98efe37f25.md)
  * T1069.002 [Get-DomainGroup with PowerView](tests/5a8a181c-2c8e-478d-a943-549305a01230.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments](tests/1c0a870f-dc74-49cf-9afc-eccc45e58790.md)
  * T1059.001 [Mimikatz](tests/f3132740-55bc-48c4-bcc0-758a459cd027.md)
* posh_ps_suspicious_local_group_reco.yml
  * T1098 [Admin Account Manipulate](tests/5598f7cb-cf43-455e-883a-f6008c5d46af.md)
  * T1087.001 [Enumerate all accounts via PowerShell (Local)](tests/ae4b6361-b5f8-46cb-a3f9-9cf108ccfe7b.md)
  * T1069.001 [WMIObject Group Discovery](tests/69119e58-96db-4110-ad27-954e48f3bb13.md)
  * T1087.002 [Enumerate all accounts via PowerShell (Domain)](tests/8b8a6449-be98-4f42-afd2-dedddc7453b2.md)
  * T1218.005 [Mshta executes VBScript to execute malicious command](tests/906865c3-e05f-4acc-85c4-fbc185455095.md)
  * T1069.001 [Permission Groups Discovery PowerShell (Local)](tests/a580462d-2c19-4bc7-8b9a-57a41b7d3ba4.md)
* posh_ps_suspicious_mail_acces.yml
  * T1114.001 [Email Collection with PowerShell Get-Inbox](tests/3f1b5096-0139-4736-9b78-19bcb02bb1cb.md)
* posh_ps_suspicious_mount_diskimage.yml
  * T1553.005 [Mount ISO image](tests/002cca30-4778-4891-878a-aaffcfa502fa.md)
  * T1553.005 [Mount an ISO image and run executable from the ISO](tests/42f22b00-0242-4afc-a61b-0da05041f9cc.md)
* posh_ps_suspicious_mounted_share_deletion.yml
  * T1553.005 [Mount ISO image](tests/002cca30-4778-4891-878a-aaffcfa502fa.md)
  * T1553.005 [Mount an ISO image and run executable from the ISO](tests/42f22b00-0242-4afc-a61b-0da05041f9cc.md)
  * T1070.005 [Remove Network Share PowerShell](tests/0512d214-9512-4d22-bde7-f37e058259b3.md)
* posh_ps_suspicious_networkcredential.yml
  * T1218.005 [Invoke HTML Application - JScript Engine with Rundll32 and Inline Protocol Handler](tests/e7e3a525-7612-4d68-a5d3-c4649181b8af.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement](tests/007e5672-2088-4853-a562-7490ddc19447.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations](tests/686a9785-f99b-41d4-90df-66ed515f81d7.md)
  * T1218.005 [Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine Simulating Double Click](tests/58a193ec-131b-404e-b1ca-b35cf0b18c33.md)
  * T1110.003 [Password spray all Active Directory domain users with a single password via LDAP against domain controller (NTLM or Kerberos)](tests/f14d956a-5b6e-4a93-847f-0c415142f07d.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1557.001 [LLMNR Poisoning with Inveigh (PowerShell)](tests/deecd55f-afe0-4a62-9fba-4d1ba2deb321.md)
  * T1218 [Invoke-ATHRemoteFXvGPUDisablementCommand base test](tests/9ebe7901-7edf-45c0-b5c7-8366300919db.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations](tests/86a43bad-12e3-4e85-b97c-4d5cf25b95c3.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments](tests/0d181431-ddf3-4826-8055-2dbf63ae848b.md)
  * T1134.004 [Parent PID Spoofing - Spawn from New Process](tests/2988133e-561c-4e42-a15f-6281e6a9b2db.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Specified Process](tests/cbbff285-9051-444a-9d17-c07cd2d230eb.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
  * T1110.001 [Brute Force Credentials of single Active Directory domain user via LDAP against domain controller (NTLM or Kerberos)](tests/c2969434-672b-4ec8-8df0-bbb91f40e250.md)
  * T1134.004 [Parent PID Spoofing - Spawn from svchost.exe](tests/e9f2b777-3123-430b-805d-5cedc66ab591.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Current Process](tests/14920ebd-1d61-491a-85e0-fe98efe37f25.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments](tests/1c0a870f-dc74-49cf-9afc-eccc45e58790.md)
* posh_ps_suspicious_new_psdrive.yml
  * T1021.002 [Map Admin Share PowerShell](tests/514e9cd7-9207-4882-98b1-c8f791bae3c5.md)
* posh_ps_suspicious_recon.yml
  * T1119 [Recon information for export with PowerShell](tests/c3f6d794-50dd-482f-b640-0384fbb7db26.md)
* posh_ps_suspicious_smb_share_reco.yml
  * T1135 [Network Share Discovery PowerShell](tests/1b0814d1-bb24-402d-9615-1b20c50733fb.md)
  * T1070.005 [Remove Network Share PowerShell](tests/0512d214-9512-4d22-bde7-f37e058259b3.md)
* posh_ps_suspicious_start_process.yml
  * T1036.003 [Masquerading - windows exe running as different windows exe](tests/c3d24a39-2bfe-4c6a-b064-90cd73896cb0.md)
  * T1218 [Invoke-ATHRemoteFXvGPUDisablementCommand base test](tests/9ebe7901-7edf-45c0-b5c7-8366300919db.md)
  * T1036.003 [Masquerading - non-windows exe running as windows exe](tests/bc15c13f-d121-4b1f-8c7d-28d95854d086.md)
* posh_ps_suspicious_unblock_file.yml
  * T1003.006 [Run DSInternals Get-ADReplAccount](tests/a0bced08-3fc5-4d8b-93b7-e8344739376e.md)
  * T1553.005 [Remove the Zone.Identifier alternate data stream](tests/64b12afc-18b8-4d3f-9eab-7f6cae7c73f9.md)
* posh_ps_suspicious_win32_pnpentity.yml
  * T1120 [Win32_PnPEntity Hardware Inventory](tests/2cb4dbf2-2dca-4597-8678-4d39d207a3a5.md)
* posh_ps_suspicious_windowstyle.yml
  * T1218.005 [Invoke HTML Application - JScript Engine with Rundll32 and Inline Protocol Handler](tests/e7e3a525-7612-4d68-a5d3-c4649181b8af.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement](tests/007e5672-2088-4853-a562-7490ddc19447.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations](tests/686a9785-f99b-41d4-90df-66ed515f81d7.md)
  * T1218.005 [Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine Simulating Double Click](tests/58a193ec-131b-404e-b1ca-b35cf0b18c33.md)
  * T1218.001 [Invoke CHM Shortcut Command with ITS and Help Topic](tests/15756147-7470-4a83-87fb-bb5662526247.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1218.001 [Invoke CHM with default Shortcut Command Execution](tests/29d6f0d7-be63-4482-8827-ea77126c1ef7.md)
  * T1218.001 [Invoke CHM with Script Engine and Help Topic](tests/4f83adda-f5ec-406d-b318-9773c9ca92e5.md)
  * T1218 [Invoke-ATHRemoteFXvGPUDisablementCommand base test](tests/9ebe7901-7edf-45c0-b5c7-8366300919db.md)
  * T1218.001 [Invoke CHM with InfoTech Storage Protocol Handler](tests/b4094750-5fc7-4e8e-af12-b4e36bf5e7f6.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations](tests/86a43bad-12e3-4e85-b97c-4d5cf25b95c3.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments](tests/0d181431-ddf3-4826-8055-2dbf63ae848b.md)
  * T1134.004 [Parent PID Spoofing - Spawn from New Process](tests/2988133e-561c-4e42-a15f-6281e6a9b2db.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Local](tests/78e95057-d429-4e66-8f82-0f060c1ac96f.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Specified Process](tests/cbbff285-9051-444a-9d17-c07cd2d230eb.md)
  * T1547.001 [SystemBC Malware-as-a-Service Registry](tests/9dc7767b-30c1-4cc4-b999-50cab5e27891.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
  * T1564.003 [Hidden Window](tests/f151ee37-9e2b-47e6-80e4-550b9f999b7a.md)
  * T1134.004 [Parent PID Spoofing - Spawn from svchost.exe](tests/e9f2b777-3123-430b-805d-5cedc66ab591.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Current Process](tests/14920ebd-1d61-491a-85e0-fe98efe37f25.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments](tests/1c0a870f-dc74-49cf-9afc-eccc45e58790.md)
  * T1218.001 [Invoke CHM Simulate Double click](tests/5decef42-92b8-4a93-9eb2-877ddcb9401a.md)
* posh_ps_tamper_defender.yml
  * T1562.001 [Tamper with Windows Defender ATP PowerShell](tests/6b8df440-51ec-4d53-bf83-899591c9b5d7.md)
* posh_ps_test_netconnection.yml
  * T1573 [OpenSSL C2](tests/21caf58e-87ad-440c-a6b8-3ac259964003.md)
  * T1571 [Testing usage of uncommonly used port with PowerShell](tests/21fe622f-8e53-4b31-ba83-6d333c2583f4.md)
* posh_ps_timestomp.yml
  * T1070.006 [Windows - Modify file last access timestamp with PowerShell](tests/da627f63-b9bd-4431-b6f8-c5b44d061a62.md)
  * T1070.006 [Windows - Timestomp a File](tests/d7512c33-3a75-4806-9893-69abc3ccdd43.md)
  * T1070.006 [Windows - Modify file creation timestamp with PowerShell](tests/b3b2c408-2ff0-4a33-b89b-1cb46a9e6a9c.md)
  * T1070.006 [Windows - Modify file last modified timestamp with PowerShell](tests/f8f6634d-93e1-4238-8510-f8a90a20dcf2.md)
* posh_ps_trigger_profiles.yml
  * T1546.013 [Append malicious start-process cmdlet](tests/090e5aa5-32b6-473b-a49b-21e843a56896.md)
* posh_ps_upload.yml
  * T1020 [IcedID Botnet HTTP PUT](tests/9c780d3d-3a14-4278-8ee5-faaeb2ccfbe0.md)
  * T1027 [DLP Evasion via Sensitive Data in VBA Macro over HTTP](tests/e2d85e66-cb66-4ed7-93b1-833fc56c9319.md)
  * T1048.003 [Exfiltration Over Alternative Protocol - HTTP](tests/6aa58451-1121-4490-a8e9-1dada3f1c68c.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Local](tests/78e95057-d429-4e66-8f82-0f060c1ac96f.md)
  * T1132.001 [XOR Encoded data.](tests/c3ed6d2a-e3ad-400d-ad78-bbfdbfeacc08.md)
  * T1041 [C2 Data Exfiltration](tests/d1253f6e-c29b-49dc-b466-2147a6191932.md)
* posh_ps_web_request.yml
  * T1105 [Windows - PowerShell Download](tests/42dc4460-9aa6-45d3-b1a6-3955d34e1fe8.md)
  * T1095 [Powercat C2](tests/3e0e0e7f-6aa2-4a61-b61d-526c2cc9330e.md)
  * T1059.001 [Run Bloodhound from Memory using Download Cradle](tests/bf8c1441-4674-4dab-8e4e-39d93d08f9b7.md)
  * T1020 [IcedID Botnet HTTP PUT](tests/9c780d3d-3a14-4278-8ee5-faaeb2ccfbe0.md)
  * T1095 [ICMP C2](tests/0268e63c-e244-42db-bef7-72a9e59fc1fc.md)
  * T1201 [Get-DomainPolicy with PowerView](tests/3177f4da-3d4b-4592-8bdc-aa23d0b2e843.md)
  * T1033 [Find computers where user has session - Stealth mode (PowerView)](tests/29857f27-a36f-4f7e-8084-4557cd6207ca.md)
  * T1197 [Bitsadmin Download (PowerShell)](tests/f63b8bc4-07e5-4112-acba-56f646f3f0bc.md)
  * T1204.002 [Office Generic Payload Download](tests/5202ee05-c420-4148-bf5e-fd7f7d24850c.md)
  * T1491.001 [Replace Desktop Wallpaper](tests/30558d53-9d76-41c4-9267-a7bd5184bed3.md)
  * T1071.004 [DNS C2](tests/e7bf9802-2e78-4db9-93b5-181b7bcd37d7.md)
  * T1027 [DLP Evasion via Sensitive Data in VBA Macro over HTTP](tests/e2d85e66-cb66-4ed7-93b1-833fc56c9319.md)
  * T1048.003 [Exfiltration Over Alternative Protocol - HTTP](tests/6aa58451-1121-4490-a8e9-1dada3f1c68c.md)
  * T1566.001 [Download Macro-Enabled Phishing Attachment](tests/114ccff9-ae6d-4547-9ead-4cd69f687306.md)
  * T1059.001 [Invoke-AppPathBypass](tests/06a220b6-7e29-4bd8-9d07-5b4d86742372.md)
  * T1059.001 [PowerUp Invoke-AllChecks](tests/1289f78d-22d2-4590-ac76-166737e1811b.md)
  * T1074.001 [Stage data from Discovery.bat](tests/107706a5-6f9f-451a-adae-bab8c667829f.md)
  * T1105 [File Download via PowerShell](tests/54a4daf1-71df-4383-9ba7-f1a295d8b6d2.md)
  * T1003.002 [PowerDump Hashes and Usernames from Registry](tests/804f28fc-68fc-40da-b5a2-e9d0bce5c193.md)
  * T1557.001 [LLMNR Poisoning with Inveigh (PowerShell)](tests/deecd55f-afe0-4a62-9fba-4d1ba2deb321.md)
  * T1071.001 [Malicious User Agents - Powershell](tests/81c13829-f6c9-45b8-85a6-053366d55297.md)
  * T1204.002 [Potentially Unwanted Applications (PUA)](tests/02f35d62-9fdc-4a97-b899-a5d9a876d295.md)
  * T1069.002 [Get-DomainGroupMember with PowerView](tests/46352f40-f283-4fe5-b56d-d9a71750e145.md)
  * T1615 [Get-DomainGPO to display group policy information via PowerView](tests/4e524c4e-0e02-49aa-8df5-93f3f7959b9f.md)
  * T1553.004 [Add Root Certificate to CurrentUser Certificate Store](tests/ca20a3f1-42b5-4e21-ad3f-1049199ec2e0.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Local](tests/78e95057-d429-4e66-8f82-0f060c1ac96f.md)
  * T1132.001 [XOR Encoded data.](tests/c3ed6d2a-e3ad-400d-ad78-bbfdbfeacc08.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Remote](tests/cab413d8-9e4a-4b8d-9b84-c985bd73a442.md)
  * T1218.005 [Mshta Executes Remote HTML Application (HTA)](tests/c4b97eeb-5249-4455-a607-59f95485cb45.md)
  * T1550.002 [Invoke-WMIExec Pass the Hash](tests/f8757545-b00a-4e4e-8cfb-8cfb961ee713.md)
  * T1087.002 [Get-DomainUser with PowerView](tests/93662494-5ed7-4454-a04c-8c8372808ac2.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
  * T1059.001 [Obfuscation Tests](tests/4297c41a-8168-4138-972d-01f3ee92c804.md)
  * T1041 [C2 Data Exfiltration](tests/d1253f6e-c29b-49dc-b466-2147a6191932.md)
  * T1069.002 [Get-DomainGroup with PowerView](tests/5a8a181c-2c8e-478d-a943-549305a01230.md)
  * T1219 [TeamViewer Files Detected Test on Windows](tests/8ca3b96d-8983-4a7f-b125-fc98cc0a2aa0.md)
  * T1059.001 [Mimikatz](tests/f3132740-55bc-48c4-bcc0-758a459cd027.md)
* posh_ps_win32_product_install_msi.yml
  * T1218.007 [WMI Win32_Product Class - Execute Local MSI file with embedded JScript](tests/882082f0-27c6-4eec-a43c-9aa80bccdb30.md)
  * T1218.007 [WMI Win32_Product Class - Execute Local MSI file with an embedded DLL](tests/32eb3861-30da-4993-897a-42737152f5f8.md)
  * T1218.007 [WMI Win32_Product Class - Execute Local MSI file with embedded VBScript](tests/cf470d9a-58e7-43e5-b0d2-805dffc05576.md)
  * T1218.007 [WMI Win32_Product Class - Execute Local MSI file with an embedded EXE](tests/55080eb0-49ae-4f55-a440-4167b7974f79.md)
* posh_ps_winlogon_helper_dll.yml
  * T1547.004 [Winlogon Userinit Key Persistence - PowerShell](tests/fb32c935-ee2e-454b-8fa3-1c46b42e8dfb.md)
  * T1547.004 [Winlogon Notify Key Logon Persistence - PowerShell](tests/d40da266-e073-4e5a-bb8b-2b385023e5f9.md)
  * T1547.004 [Winlogon Shell Key Persistence - PowerShell](tests/bf9f9d65-ee4d-4c3e-a843-777d04f19c38.md)
* posh_ps_wmi_persistence.yml
  * T1546.003 [Persistence via WMI Event Subscription](tests/3c64f177-28e2-49eb-a799-d767b24dd1e0.md)
* posh_ps_xml_iex.yml
  * T1059.001 [Powershell XML requests](tests/4396927f-e503-427b-b023-31049b9b09a6.md)
* proc_access_win_cred_dump_lsass_access.yml
  * T1003.001 [Dump LSASS.exe Memory using ProcDump](tests/0be2230c-9ab3-4ac2-8826-3199b9a0ebf8.md)
  * T1036.003 [Masquerading as Windows LSASS process](tests/5ba5a3d1-cf3c-4499-968a-a93155d1f717.md)
  * T1134.002 [Access Token Manipulation](tests/dbf4f5a9-b8e0-46a3-9841-9ad71247239e.md)
  * T1003.001 [Create Mini Dump of LSASS.exe using ProcDump](tests/7cede33f-0acd-44ef-9774-15511300b24b.md)
  * T1003.002 [PowerDump Hashes and Usernames from Registry](tests/804f28fc-68fc-40da-b5a2-e9d0bce5c193.md)
  * T1003.001 [Dump LSASS.exe Memory using comsvcs.dll](tests/2536dee2-12fb-459a-8c37-971844fa73be.md)
  * T1003.001 [Dump LSASS.exe Memory using NanoDump](tests/dddd4aca-bbed-46f0-984d-e4c5971c51ea.md)
  * T1003.001 [Dump LSASS.exe using imported Microsoft DLLs](tests/86fc3f40-237f-4701-b155-81c01c48d697.md)
  * T1562.001 [Disable Defender Using NirSoft AdvancedRun](tests/81ce22fd-9612-4154-918e-8a1f285d214d.md)
  * T1003.001 [Dump LSASS.exe Memory using Out-Minidump.ps1](tests/6502c8f0-b775-4dbd-9193-1298f56b6781.md)
* proc_access_win_in_memory_assembly_execution.yml
  * T1055.004 [Process Injection via C#](tests/611b39b7-e243-4c81-87a4-7145a90358b1.md)
  * T1003.001 [Dump LSASS.exe Memory using Windows Task Manager](tests/dea6c349-f1c6-44f3-87a1-1ed33a59a607.md)
  * T1055 [Shellcode execution via VBA](tests/1c91e740-1729-4329-b779-feba6e71d048.md)
  * T1106 [Execution through API - CreateProcess](tests/99be2089-c52d-4a4a-b5c3-261ee42c8b62.md)
* proc_access_win_lsass_dump_comsvcs_dll.yml
  * T1003.001 [Dump LSASS.exe Memory using comsvcs.dll](tests/2536dee2-12fb-459a-8c37-971844fa73be.md)
* proc_access_win_lsass_memdump.yml
  * T1003.001 [Dump LSASS.exe Memory using ProcDump](tests/0be2230c-9ab3-4ac2-8826-3199b9a0ebf8.md)
  * T1003.001 [Create Mini Dump of LSASS.exe using ProcDump](tests/7cede33f-0acd-44ef-9774-15511300b24b.md)
  * T1003.001 [Dump LSASS.exe Memory using comsvcs.dll](tests/2536dee2-12fb-459a-8c37-971844fa73be.md)
  * T1003.001 [Dump LSASS.exe Memory using Windows Task Manager](tests/dea6c349-f1c6-44f3-87a1-1ed33a59a607.md)
  * T1003.001 [Dump LSASS.exe Memory using direct system calls and API unhooking](tests/7ae7102c-a099-45c8-b985-4c7a2d05790d.md)
  * T1003.001 [Dump LSASS.exe using imported Microsoft DLLs](tests/86fc3f40-237f-4701-b155-81c01c48d697.md)
* proc_access_win_pypykatz_cred_dump_lsass_access.yml
  * T1003.001 [LSASS read with pypykatz](tests/c37bc535-5c62-4195-9cc3-0517673171d8.md)
* proc_access_win_rare_proc_access_lsass.yml
  * T1562.001 [Disable Defender Using NirSoft AdvancedRun](tests/81ce22fd-9612-4154-918e-8a1f285d214d.md)
* proc_access_win_susp_proc_access_lsass.yml
  * T1003.001 [Dump LSASS.exe Memory using ProcDump](tests/0be2230c-9ab3-4ac2-8826-3199b9a0ebf8.md)
  * T1003.001 [Create Mini Dump of LSASS.exe using ProcDump](tests/7cede33f-0acd-44ef-9774-15511300b24b.md)
  * T1550.002 [Mimikatz Pass the Hash](tests/ec23cef9-27d9-46e4-a68d-6f75f7b86908.md)
  * T1003.001 [Dump LSASS.exe Memory using NanoDump](tests/dddd4aca-bbed-46f0-984d-e4c5971c51ea.md)
  * T1003 [Gsecdump](tests/96345bfc-8ae7-4b6a-80b7-223200f24ef9.md)
* proc_access_win_susp_proc_access_lsass_susp_source.yml
  * T1204.002 [Excel 4 Macro](tests/4ea1fc97-8a46-4b4e-ba48-af43d2a98052.md)
  * T1550.002 [Mimikatz Pass the Hash](tests/ec23cef9-27d9-46e4-a68d-6f75f7b86908.md)
  * T1003.001 [Dump LSASS.exe Memory using NanoDump](tests/dddd4aca-bbed-46f0-984d-e4c5971c51ea.md)
  * T1003 [Gsecdump](tests/96345bfc-8ae7-4b6a-80b7-223200f24ef9.md)
  * T1003.001 [Dump LSASS.exe using imported Microsoft DLLs](tests/86fc3f40-237f-4701-b155-81c01c48d697.md)
  * T1562.001 [Disable Defender Using NirSoft AdvancedRun](tests/81ce22fd-9612-4154-918e-8a1f285d214d.md)
* proc_creation_win_abusing_debug_privilege.yml
  * T1563.002 [RDP hijacking](tests/a37ac520-b911-458e-8aed-c5f1576d9f46.md)
  * T1569.002 [Execute a Command as a Service](tests/2382dee2-a75f-49aa-9378-f52df6ed3fb1.md)
* proc_creation_win_ad_find_discovery.yml
  * T1018 [Adfind - Enumerate Active Directory Computer Objects](tests/a889f5be-2d54-4050-bd05-884578748bb4.md)
  * T1016 [Adfind - Enumerate Active Directory Subnet Objects](tests/9bb45dd7-c466-4f93-83a1-be30e56033ee.md)
  * T1018 [Enumerate domain computers within Active Directory using DirectorySearcher](tests/962a6017-1c09-45a6-880b-adc9c57cb22e.md)
  * T1087.002 [Enumerate Linked Policies In ADSISearcher Discovery](tests/7ab0205a-34e4-4a44-9b04-e1541d1a57be.md)
  * T1018 [Enumerate Active Directory Computers with ADSISearcher](tests/64ede6ac-b57a-41c2-a7d1-32c6cd35397d.md)
  * T1087.002 [Enumerate Active Directory Users with ADSISearcher](tests/02e8be5a-3065-4e54-8cc8-a14d138834d3.md)
  * T1069.002 [Adfind - Query Active Directory Groups](tests/48ddc687-82af-40b7-8472-ff1e742e8274.md)
  * T1482 [Adfind - Enumerate Active Directory Trusts](tests/15fe436d-e771-4ff3-b655-2dca9ba52834.md)
  * T1069.002 [Enumerate Active Directory Groups with ADSISearcher](tests/9f4e344b-8434-41b3-85b1-d38f29d148d0.md)
  * T1482 [Adfind - Enumerate Active Directory OUs](tests/d1c73b96-ab87-4031-bad8-0e1b3b8bf3ec.md)
  * T1087.002 [Adfind - Enumerate Active Directory User Objects](tests/e1ec8d20-509a-4b9a-b820-06c9b2da8eb7.md)
* proc_creation_win_alternate_data_streams.yml
  * T1564.004 [Alternate Data Streams (ADS)](tests/8822c3b0-d9f9-4daf-a043-49f4602364f4.md)
* proc_creation_win_always_install_elevated_windows_installer.yml
  * T1219 [LogMeIn Files Detected Test on Windows](tests/d03683ec-aae0-42f9-9b4c-534780e0f8e1.md)
  * T1219 [RemotePC Software Execution](tests/fbff3f1f-b0bf-448e-840f-7e1687affdce.md)
* proc_creation_win_anydesk.yml
  * T1219 [AnyDesk Files Detected Test on Windows](tests/6b8b7391-5c0a-4f8c-baee-78d8ce0ce330.md)
* proc_creation_win_apt_bluemashroom.yml
  * T1218.010 [Regsvr32 Registering Non DLL](tests/1ae5ea1f-0a4e-4e54-b2f5-4ac328a7f421.md)
* proc_creation_win_apt_dragonfly.yml
  * T1550.002 [crackmapexec Pass the Hash](tests/eb05b028-16c8-4ad8-adea-6f5b219da9a9.md)
* proc_creation_win_apt_hurricane_panda.yml
  * T1078.003 [Create local account with admin privileges](tests/a524ce99-86de-4db6-b4f9-e08f35a47a15.md)
  * T1078.001 [Enable Guest account with RDP capability and admin privileges](tests/99747561-ed8d-47f2-9c91-1e5fde1ed6e0.md)
  * T1136.001 [Create a new Windows admin user](tests/fda74566-a604-4581-a4cc-fbbe21d66559.md)
* proc_creation_win_apt_lazarus_activity_apr21.yml
  * T1218.005 [Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
* proc_creation_win_apt_ta505_dropper.yml
  * T1218.005 [Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
* proc_creation_win_apt_unc2452_cmds.yml
  * T1218.002 [Control Panel Items](tests/037e9d8a-9e46-4255-8b33-2ae3b545ca6f.md)
* proc_creation_win_apt_wocao.yml
  * T1036.004 [Creating W32Time similar named service using sc](tests/b721c6ef-472c-4263-a0d9-37f1f4ecff66.md)
  * T1036.004 [Creating W32Time similar named service using schtasks](tests/f9f2fe59-96f7-4a7d-ba9f-a9783200d4c9.md)
* proc_creation_win_attrib_hiding_files.yml
  * T1222.001 [attrib - hide file](tests/32b979da-7b68-42c9-9a99-0e39900fc36c.md)
  * T1564.001 [Create Windows Hidden File with Attrib](tests/dadb792e-4358-4d8d-9207-b771faa0daa5.md)
* proc_creation_win_attrib_system.yml
  * T1564.001 [Create Windows System File with Attrib](tests/f70974c8-c094-4574-b542-2c545af95a32.md)
* proc_creation_win_automated_collection.yml
  * T1119 [Automated Collection Command Prompt](tests/cb379146-53f1-43e0-b884-7ce2c635ff5b.md)
  * T1552.001 [Extracting passwords with findstr](tests/0e56bf29-ff49-4ea5-9af4-3b81283fd513.md)
* proc_creation_win_bad_opsec_sacrificial_processes.yml
  * T1055 [Shellcode execution via VBA](tests/1c91e740-1729-4329-b779-feba6e71d048.md)
* proc_creation_win_bitsadmin_download.yml
  * T1197 [Bitsadmin Download (cmd)](tests/3c73d728-75fb-4180-a12f-6712864d7421.md)
  * T1105 [Windows - BITSAdmin BITS Download](tests/a1921cd3-9a2d-47d5-a891-f1d0f2a7a31b.md)
  * T1197 [Persist, Download, & Execute](tests/62a06ec5-5754-47d2-bcfc-123d8314c6ae.md)
* proc_creation_win_bootconf_mod.yml
  * T1490 [Windows - Disable Windows Recovery Console Repair](tests/cf21060a-80b3-4238-a595-22525de4ab81.md)
* proc_creation_win_bypass_squiblytwo.yml
  * T1220 [WMIC bypass using remote XSL file](tests/7f5be499-33be-4129-a560-66021f379b9b.md)
* proc_creation_win_change_default_file_association.yml
  * T1546.001 [Change Default File Association](tests/10a08978-2045-4d62-8c42-1957bbbea102.md)
* proc_creation_win_clip.yml
  * T1115 [Utilize Clipboard to store or execute commands from](tests/0cd14633-58d4-4422-9ede-daa2c9474ae7.md)
* proc_creation_win_cmd_delete.yml
  * T1070.004 [Delete a single file - Windows cmd](tests/861ea0b4-708a-4d17-848d-186c9c7f17e3.md)
  * T1070.004 [Delete an entire folder - Windows cmd](tests/ded937c4-2add-42f7-9c2c-c742b7a98698.md)
* proc_creation_win_cmd_redirect.yml
  * T1059.003 [Suspicious Execution via Windows Command Shell](tests/d0eb3597-a1b3-4d65-b33b-2cda8d397f20.md)
  * T1564.004 [Create ADS command prompt](tests/17e7637a-ddaf-4a82-8622-377e20de8fdb.md)
  * T1071.001 [Malicious User Agents - CMD](tests/dc3488b0-08c7-4fea-b585-905c83b48180.md)
  * T1105 [Download a file with Microsoft Connection Manager Auto-Download](tests/d239772b-88e2-4a2e-8473-897503401bcc.md)
  * T1059.003 [Writes text to a file and displays it.](tests/127b4afe-2346-4192-815c-69042bec570e.md)
* proc_creation_win_cmdkey_recon.yml
  * T1087.001 [Enumerate all accounts via PowerShell (Local)](tests/ae4b6361-b5f8-46cb-a3f9-9cf108ccfe7b.md)
  * T1003.005 [Cached Credential Dump via Cmdkey](tests/56506854-89d6-46a3-9804-b7fde90791f9.md)
  * T1087.001 [Enumerate all accounts on Windows (Local)](tests/80887bec-5a9b-4efc-a81d-f83eb2eb32ab.md)
* proc_creation_win_control_panel_item.yml
  * T1218.002 [Control Panel Items](tests/037e9d8a-9e46-4255-8b33-2ae3b545ca6f.md)
* proc_creation_win_copying_sensitive_files_with_credential_data.yml
  * T1003.002 [dump volume shadow copy hives with certutil](tests/eeb9751a-d598-42d3-b11c-c122d9c3f6c7.md)
  * T1564.004 [Alternate Data Streams (ADS)](tests/8822c3b0-d9f9-4daf-a043-49f4602364f4.md)
  * T1003.003 [Create Volume Shadow Copy remotely (WMI) with esentutl](tests/21c7bf80-3e8b-40fa-8f9d-f5b194ff2865.md)
  * T1003.002 [esentutl.exe SAM copy](tests/a90c2f4d-6726-444e-99d2-a00cd7c20480.md)
  * T1003.003 [Copy NTDS.dit from Volume Shadow Copy](tests/c6237146-9ea6-4711-85c9-c56d263a6b03.md)
  * T1003.002 [dump volume shadow copy hives with System.IO.File](tests/9d77fed7-05f8-476e-a81b-8ff0472c64d0.md)
* proc_creation_win_creation_mavinject_dll.yml
  * T1218 [mavinject - Inject DLL into running process](tests/c426dacf-575d-4937-8611-a148a86a5e61.md)
  * T1056.004 [Hook PowerShell TLS Encrypt/Decrypt Messages](tests/de1934ea-1fbf-425b-8795-65fb27dd7e33.md)
  * T1055.001 [Process Injection via mavinject.exe](tests/74496461-11a1-4982-b439-4d87a550d254.md)
* proc_creation_win_data_compressed_with_rar.yml
  * T1560.001 [Compress Data for Exfiltration With Rar](tests/02ea31cb-3b4c-4a2d-9bf1-e4e70ebcf5d0.md)
  * T1560.001 [Compress Data and lock with password for Exfiltration with winrar](tests/8dd61a55-44c6-43cc-af0c-8bdda276860c.md)
* proc_creation_win_delete_systemstatebackup.yml
  * T1490 [Windows - wbadmin Delete systemstatebackup](tests/584331dd-75bc-4c02-9e0b-17f5fd81c748.md)
* proc_creation_win_dinjector.yml
  * T1550.003 [Rubeus Kerberos Pass The Ticket](tests/a2fc4ec5-12c6-4fb4-b661-961f23f359cb.md)
* proc_creation_win_discover_private_keys.yml
  * T1552.004 [Private Keys](tests/520ce462-7ca7-441e-b5a5-f8347f632696.md)
* proc_creation_win_dsim_remove.yml
  * T1562.001 [Disable Windows Defender with DISM](tests/871438ac-7d6e-432a-b27d-3e7db69faf58.md)
* proc_creation_win_enumeration_for_credentials_in_registry.yml
  * T1552.002 [Enumeration for Credentials in Registry](tests/b6ec082c-7384-46b3-a111-9a9b8b14e5e7.md)
  * T1552.002 [Enumeration for PuTTY Credentials in Registry](tests/af197fd7-e868-448e-9bd5-05d1bcd9d9e5.md)
* proc_creation_win_etw_trace_evasion.yml
  * T1562.006 [Disable Powershell ETW Provider - Windows](tests/6f118276-121d-4c09-bb58-a8fb4a72ee84.md)
  * T1562.002 [Disable Event Logging with wevtutil](tests/b26a3340-dad7-4360-9176-706269c74103.md)
* proc_creation_win_evil_winrm.yml
  * T1021.006 [WinRM Access with Evil-WinRM](tests/efe86d95-44c4-4509-ae42-7bfd9d1f5b3d.md)
* proc_creation_win_false_sysinternalsuite.yml
  * T1555.003 [Run Chrome-password Collector](tests/8c05b133-d438-47ca-a630-19cc464c4622.md)
* proc_creation_win_file_permission_modifications.yml
  * T1546.008 [Replace binary of sticky keys](tests/934e90cf-29ca-48b3-863c-411737ad44e3.md)
  * T1222.001 [attrib - Remove read-only attribute](tests/bec1e95c-83aa-492e-ab77-60c71bbd21b0.md)
  * T1222.001 [cacls - Grant permission to specified user or group recursively](tests/a8206bcc-f282-40a9-a389-05d9c0263485.md)
  * T1222.001 [Grant Full Access to folder for Everyone - Ryuk Ransomware Style](tests/ac7e6118-473d-41ec-9ac0-ef4f1d1ed2f6.md)
* proc_creation_win_findstr_gpp_passwords.yml
  * T1552.006 [GPP Passwords (findstr)](tests/870fe8fb-5e23-4f5f-b89d-dd7fe26f3b5f.md)
* proc_creation_win_gotoopener.yml
  * T1219 [GoToAssist Files Detected Test on Windows](tests/1b72b3bd-72f8-4b63-a30b-84e91b9c3578.md)
  * T1219 [LogMeIn Files Detected Test on Windows](tests/d03683ec-aae0-42f9-9b4c-534780e0f8e1.md)
* proc_creation_win_hack_bloodhound.yml
  * T1059.001 [Run Bloodhound from Memory using Download Cradle](tests/bf8c1441-4674-4dab-8e4e-39d93d08f9b7.md)
  * T1059.001 [Run BloodHound from local disk](tests/a21bb23e-e677-4ee7-af90-6931b57b6350.md)
  * T1069.001 [SharpHound3 - LocalAdmin](tests/e03ada14-0980-4107-aff1-7783b2b59bb1.md)
* proc_creation_win_hack_dumpert.yml
  * T1003.001 [Dump LSASS.exe Memory using direct system calls and API unhooking](tests/7ae7102c-a099-45c8-b985-4c7a2d05790d.md)
* proc_creation_win_hack_rubeus.yml
  * T1550.003 [Rubeus Kerberos Pass The Ticket](tests/a2fc4ec5-12c6-4fb4-b661-961f23f359cb.md)
  * T1558.001 [Crafting Active Directory golden tickets with Rubeus](tests/e42d33cd-205c-4acf-ab59-a9f38f6bad9c.md)
  * T1558.004 [Rubeus asreproast](tests/615bd568-2859-41b5-9aed-61f6a88e48dd.md)
* proc_creation_win_hacktool_imphashes.yml
  * T1558.002 [Crafting Active Directory silver tickets with mimikatz](tests/385e59aa-113e-4711-84d9-f637aef01f2c.md)
* proc_creation_win_hashcat.yml
  * T1110.002 [Password Cracking with Hashcat](tests/6d27df5d-69d4-4c91-bc33-5983ffe91692.md)
* proc_creation_win_hh_chm.yml
  * T1218.001 [Invoke CHM Shortcut Command with ITS and Help Topic](tests/15756147-7470-4a83-87fb-bb5662526247.md)
  * T1218.001 [Invoke CHM with default Shortcut Command Execution](tests/29d6f0d7-be63-4482-8827-ea77126c1ef7.md)
  * T1218.001 [Invoke CHM with Script Engine and Help Topic](tests/4f83adda-f5ec-406d-b318-9773c9ca92e5.md)
  * T1218.001 [Invoke CHM with InfoTech Storage Protocol Handler](tests/b4094750-5fc7-4e8e-af12-b4e36bf5e7f6.md)
  * T1218.001 [Compiled HTML Help Local Payload](tests/5cb87818-0d7c-4469-b7ef-9224107aebe8.md)
  * T1218.001 [Compiled HTML Help Remote Payload](tests/0f8af516-9818-4172-922b-42986ef1e81d.md)
  * T1218.001 [Invoke CHM Simulate Double click](tests/5decef42-92b8-4a93-9eb2-877ddcb9401a.md)
* proc_creation_win_high_integrity_sdclt.yml
  * T1059.001 [Invoke-AppPathBypass](tests/06a220b6-7e29-4bd8-9d07-5b4d86742372.md)
  * T1548.002 [Bypass UAC using sdclt DelegateExecute](tests/3be891eb-4608-4173-87e8-78b494c029b7.md)
* proc_creation_win_hktl_uacme_uac_bypass.yml
  * T1548.002 [UACME Bypass Method 31](tests/b0f76240-9f33-4d34-90e8-3a7d501beb15.md)
  * T1548.002 [UACME Bypass Method 23](tests/8ceab7a2-563a-47d2-b5ba-0995211128d7.md)
  * T1548.002 [UACME Bypass Method 59](tests/dfb1b667-4bb8-4a63-a85e-29936ea75f29.md)
  * T1548.002 [UACME Bypass Method 56](tests/235ec031-cd2d-465d-a7ae-68bab281e80e.md)
  * T1548.002 [UACME Bypass Method 61](tests/7825b576-744c-4555-856d-caf3460dc236.md)
  * T1548.002 [UACME Bypass Method 34](tests/695b2dac-423e-448e-b6ef-5b88e93011d6.md)
  * T1548.002 [UACME Bypass Method 33](tests/e514bb03-f71c-4b22-9092-9f961ec6fb03.md)
  * T1548.002 [UACME Bypass Method 39](tests/56163687-081f-47da-bb9c-7b231c5585cf.md)
* proc_creation_win_html_help_spawn.yml
  * T1218.001 [Invoke CHM Shortcut Command with ITS and Help Topic](tests/15756147-7470-4a83-87fb-bb5662526247.md)
  * T1218.001 [Invoke CHM with default Shortcut Command Execution](tests/29d6f0d7-be63-4482-8827-ea77126c1ef7.md)
  * T1218.001 [Invoke CHM with Script Engine and Help Topic](tests/4f83adda-f5ec-406d-b318-9773c9ca92e5.md)
  * T1218.001 [Invoke CHM with InfoTech Storage Protocol Handler](tests/b4094750-5fc7-4e8e-af12-b4e36bf5e7f6.md)
  * T1218.001 [Compiled HTML Help Local Payload](tests/5cb87818-0d7c-4469-b7ef-9224107aebe8.md)
  * T1218.001 [Invoke CHM Simulate Double click](tests/5decef42-92b8-4a93-9eb2-877ddcb9401a.md)
* proc_creation_win_iis_http_logging.yml
  * T1562.002 [Disable Windows IIS HTTP Logging](tests/69435dcf-c66f-4ec0-a8b1-82beb76b34db.md)
* proc_creation_win_indirect_cmd.yml
  * T1202 [Indirect Command Execution - forfiles.exe](tests/8b34a448-40d9-4fc3-a8c8-4bb286faf7dc.md)
  * T1202 [Indirect Command Execution - pcalua.exe](tests/cecfea7a-5f03-4cdd-8bc8-6f7c22862440.md)
* proc_creation_win_infdefaultinstall.yml
  * T1218 [InfDefaultInstall.exe .inf Execution](tests/54ad7d5a-a1b5-472c-b6c4-f8090fb2daef.md)
* proc_creation_win_install_reg_debugger_backdoor.yml
  * T1546.008 [Attaches Command Prompt as a Debugger to a List of Target Processes](tests/3309f53e-b22b-4eb6-8fd2-a6cf58b355a9.md)
* proc_creation_win_interactive_at.yml
  * T1053.002 [At.exe Scheduled task](tests/4a6c0dc4-0f2a-4203-9298-a5a9bdc21ed8.md)
* proc_creation_win_lethalhta.yml
  * T1218.005 [Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement](tests/007e5672-2088-4853-a562-7490ddc19447.md)
* proc_creation_win_local_system_owner_account_discovery.yml
  * T1036.003 [File Extension Masquerading](tests/c7fa0c3b-b57f-4cba-9118-863bf4e653fc.md)
  * T1087.001 [Enumerate logged on users via CMD (Local)](tests/a138085e-bfe5-46ba-a242-74a6fb884af3.md)
  * T1003.005 [Cached Credential Dump via Cmdkey](tests/56506854-89d6-46a3-9804-b7fde90791f9.md)
  * T1087.002 [Enumerate logged on users via CMD (Domain)](tests/161dcd85-d014-4f5e-900c-d3eaae82a0f7.md)
  * T1110.001 [Brute Force Credentials of single Active Directory domain users via SMB](tests/09480053-2f98-4854-be6e-71ae5f672224.md)
  * T1083 [File and Directory Discovery (cmd.exe)](tests/0e36303b-6762-4500-b003-127743b80ba6.md)
  * T1047 [WMI Reconnaissance Users](tests/c107778c-dcf5-47c5-af2e-1d058a3df3ea.md)
  * T1078.003 [Create local account with admin privileges](tests/a524ce99-86de-4db6-b4f9-e08f35a47a15.md)
  * T1563.002 [RDP hijacking](tests/a37ac520-b911-458e-8aed-c5f1576d9f46.md)
  * T1078.001 [Enable Guest account with RDP capability and admin privileges](tests/99747561-ed8d-47f2-9c91-1e5fde1ed6e0.md)
  * T1033 [System Owner/User Discovery](tests/4c4959bf-addf-4b4a-be86-8d09cc1857aa.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
  * T1110.003 [Password Spray all Domain Users](tests/90bc2e54-6c84-47a5-9439-0a2a92b4b175.md)
* proc_creation_win_logmein.yml
  * T1219 [GoToAssist Files Detected Test on Windows](tests/1b72b3bd-72f8-4b63-a30b-84e91b9c3578.md)
  * T1219 [LogMeIn Files Detected Test on Windows](tests/d03683ec-aae0-42f9-9b4c-534780e0f8e1.md)
* proc_creation_win_logon_scripts_userinitmprlogonscript_proc.yml
  * T1037.001 [Logon Scripts](tests/d6042746-07d4-4c92-9ad8-e644c114a231.md)
* proc_creation_win_lolbas_configsecuritypolicy.yml
  * T1567 [Data Exfiltration with ConfigSecurityPolicy](tests/5568a8f4-a8b1-4c40-9399-4969b642f122.md)
* proc_creation_win_lolbas_execution_of_wuauclt.yml
  * T1218 [Load Arbitrary DLL via Wuauclt (Windows Update Client)](tests/49fbd548-49e9-4bb7-94a6-3769613912b8.md)
* proc_creation_win_lolbas_replace.yml
  * T1558.002 [Crafting Active Directory silver tickets with mimikatz](tests/385e59aa-113e-4711-84d9-f637aef01f2c.md)
* proc_creation_win_lolbins_suspicious_driver_installed_by_pnputil.yml
  * T1547 [Add a driver](tests/cb01b3da-b0e7-4e24-bf6d-de5223526785.md)
* proc_creation_win_long_powershell_commandline.yml
  * T1036.003 [File Extension Masquerading](tests/c7fa0c3b-b57f-4cba-9118-863bf4e653fc.md)
  * T1059.001 [Mimikatz - Cradlecraft PsSendKeys](tests/af1800cf-9f9d-4fd1-a709-14b1e6de020d.md)
* proc_creation_win_lsass_dump.yml
  * T1003.001 [Dump LSASS.exe Memory using ProcDump](tests/0be2230c-9ab3-4ac2-8826-3199b9a0ebf8.md)
  * T1003.001 [Dump LSASS with .Net 5 createdump.exe](tests/9d0072c8-7cca-45c4-bd14-f852cfa35cf0.md)
  * T1003.001 [Create Mini Dump of LSASS.exe using ProcDump](tests/7cede33f-0acd-44ef-9774-15511300b24b.md)
  * T1003.001 [Dump LSASS.exe Memory using comsvcs.dll](tests/2536dee2-12fb-459a-8c37-971844fa73be.md)
  * T1003.001 [Offline Credential Theft With Mimikatz](tests/453acf13-1dbd-47d7-b28a-172ce9228023.md)
  * T1003.001 [Dump LSASS.exe using imported Microsoft DLLs](tests/86fc3f40-237f-4701-b155-81c01c48d697.md)
* proc_creation_win_malware_conti_shadowcopy.yml
  * T1003.002 [dump volume shadow copy hives with certutil](tests/eeb9751a-d598-42d3-b11c-c122d9c3f6c7.md)
  * T1003.003 [Create Symlink to Volume Shadow Copy](tests/21748c28-2793-4284-9e07-d6d028b66702.md)
  * T1003.003 [Copy NTDS.dit from Volume Shadow Copy](tests/c6237146-9ea6-4711-85c9-c56d263a6b03.md)
  * T1003.002 [dump volume shadow copy hives with System.IO.File](tests/9d77fed7-05f8-476e-a81b-8ff0472c64d0.md)
* proc_creation_win_malware_script_dropper.yml
  * T1547.001 [Suspicious vbs file run from startup Folder](tests/2cb98256-625e-4da9-9d44-f2e5f90b8bd5.md)
  * T1204.002 [OSTAP JS version](tests/add560ef-20d6-4011-a937-2c340f930911.md)
  * T1036.003 [File Extension Masquerading](tests/c7fa0c3b-b57f-4cba-9118-863bf4e653fc.md)
  * T1204.002 [Excel 4 Macro](tests/4ea1fc97-8a46-4b4e-ba48-af43d2a98052.md)
  * T1547.001 [Suspicious jse file run from startup Folder](tests/dade9447-791e-4c8f-b04b-3a35855dfa06.md)
  * T1204.002 [OSTap Style Macro Execution](tests/8bebc690-18c7-4549-bc98-210f7019efff.md)
  * T1204.002 [OSTap Payload Download](tests/3f3af983-118a-4fa1-85d3-ba4daa739d80.md)
* proc_creation_win_malware_wannacry.yml
  * T1490 [Windows - Disable Windows Recovery Console Repair](tests/cf21060a-80b3-4238-a595-22525de4ab81.md)
  * T1490 [Windows - wbadmin Delete Windows Backup Catalog](tests/263ba6cb-ea2b-41c9-9d4e-b652dadd002c.md)
  * T1222.001 [Grant Full Access to folder for Everyone - Ryuk Ransomware Style](tests/ac7e6118-473d-41ec-9ac0-ef4f1d1ed2f6.md)
* proc_creation_win_manage_bde_lolbas.yml
  * T1216 [manage-bde.wsf Signed Script Command Execution](tests/2a8f2d3c-3dec-4262-99dd-150cb2a4d63a.md)
* proc_creation_win_mavinject_proc_inj.yml
  * T1218 [mavinject - Inject DLL into running process](tests/c426dacf-575d-4937-8611-a148a86a5e61.md)
  * T1055.001 [Process Injection via mavinject.exe](tests/74496461-11a1-4982-b439-4d87a550d254.md)
* proc_creation_win_mimikatz_command_line.yml
  * T1207 [DCShadow (Active Directory)](tests/0f4c5eb0-98a0-4496-9c3d-656b4f2bc8f6.md)
  * T1550.003 [Mimikatz Kerberos Ticket Attack](tests/dbf38128-7ba7-4776-bedf-cc2eed432098.md)
  * T1134.005 [Injection SID-History with mimikatz](tests/6bef32e5-9456-4072-8f14-35566fb85401.md)
  * T1059.001 [PowerShell Invoke Known Malicious Cmdlets](tests/49eb9404-5e0f-4031-a179-b40f7be385e3.md)
  * T1550.002 [Mimikatz Pass the Hash](tests/ec23cef9-27d9-46e4-a68d-6f75f7b86908.md)
  * T1110.003 [Password spray all Active Directory domain users with a single password via LDAP against domain controller (NTLM or Kerberos)](tests/f14d956a-5b6e-4a93-847f-0c415142f07d.md)
  * T1003.001 [Offline Credential Theft With Mimikatz](tests/453acf13-1dbd-47d7-b28a-172ce9228023.md)
  * T1558.002 [Crafting Active Directory silver tickets with mimikatz](tests/385e59aa-113e-4711-84d9-f637aef01f2c.md)
  * T1216 [SyncAppvPublishingServer Signed Script PowerShell Command Execution](tests/275d963d-3f36-476c-8bef-a2a3960ee6eb.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Remote](tests/cab413d8-9e4a-4b8d-9b84-c985bd73a442.md)
  * T1003.006 [DCSync (Active Directory)](tests/129efd28-8497-4c87-a1b0-73b9a870ca3e.md)
  * T1110.001 [Brute Force Credentials of single Active Directory domain user via LDAP against domain controller (NTLM or Kerberos)](tests/c2969434-672b-4ec8-8df0-bbb91f40e250.md)
  * T1558.001 [Crafting Active Directory golden tickets with mimikatz](tests/9726592a-dabc-4d4d-81cd-44070008b3af.md)
  * T1059.001 [Mimikatz - Cradlecraft PsSendKeys](tests/af1800cf-9f9d-4fd1-a709-14b1e6de020d.md)
  * T1003.001 [Dump LSASS.exe Memory using Out-Minidump.ps1](tests/6502c8f0-b775-4dbd-9193-1298f56b6781.md)
* proc_creation_win_mmc20_lateral_movement.yml
  * T1021.003 [PowerShell Lateral Movement using MMC20](tests/6dc74eb1-c9d6-4c53-b3b5-6f50ae339673.md)
* proc_creation_win_modif_of_services_for_via_commandline.yml
  * T1543.003 [Modify Fax service to run PowerShell](tests/ed366cde-7d12-49df-a833-671904770b9f.md)
* proc_creation_win_monitoring_for_persistence_via_bits.yml
  * T1197 [Persist, Download, & Execute](tests/62a06ec5-5754-47d2-bcfc-123d8314c6ae.md)
* proc_creation_win_mshta_javascript.yml
  * T1218.005 [Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject](tests/1483fab9-4f52-4217-a9ce-daa9d7747cae.md)
  * T1059.001 [Powershell invoke mshta.exe download](tests/8a2ad40b-12c7-4b25-8521-2737b0a415af.md)
* proc_creation_win_mshta_spawn_shell.yml
  * T1218.005 [Mshta used to Execute PowerShell](tests/8707a805-2b76-4f32-b1c0-14e558205772.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement](tests/007e5672-2088-4853-a562-7490ddc19447.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
  * T1218.005 [Mshta Executes Remote HTML Application (HTA)](tests/c4b97eeb-5249-4455-a607-59f95485cb45.md)
  * T1218.005 [Mshta executes VBScript to execute malicious command](tests/906865c3-e05f-4acc-85c4-fbc185455095.md)
  * T1059.001 [Powershell invoke mshta.exe download](tests/8a2ad40b-12c7-4b25-8521-2737b0a415af.md)
* proc_creation_win_msiexec_dll.yml
  * T1218.007 [Msiexec.exe - Execute the DllUnregisterServer function of a DLL](tests/ab09ec85-4955-4f9c-b8e0-6851baf4d47f.md)
* proc_creation_win_msiexec_embedding.yml
  * T1218.007 [Msiexec.exe - Execute Local MSI file with embedded JScript](tests/a059b6c4-e7d6-4b2e-bcd7-9b2b33191a04.md)
  * T1218.007 [Msiexec.exe - Execute Local MSI file with an embedded DLL](tests/628fa796-76c5-44c3-93aa-b9d8214fd568.md)
  * T1218.007 [Msiexec.exe - Execute Local MSI file with embedded VBScript](tests/8d73c7b0-c2b1-4ac1-881a-4aa644f76064.md)
* proc_creation_win_msiexec_execute_dll.yml
  * T1218.007 [Msiexec.exe - Execute the DllRegisterServer function of a DLL](tests/0106ffa5-fab6-4c7d-82e3-e6b8867d5e5d.md)
* proc_creation_win_msiexec_install_quiet.yml
  * T1218.007 [Msiexec.exe - Execute Local MSI file with embedded JScript](tests/a059b6c4-e7d6-4b2e-bcd7-9b2b33191a04.md)
  * T1219 [LogMeIn Files Detected Test on Windows](tests/d03683ec-aae0-42f9-9b4c-534780e0f8e1.md)
  * T1218.007 [Msiexec.exe - Execute Remote MSI file](tests/44a4bedf-ffe3-452e-bee4-6925ab125662.md)
  * T1218.007 [Msiexec.exe - Execute Local MSI file with an embedded EXE](tests/ed3fa08a-ca18-4009-973e-03d13014d0e8.md)
  * T1218.007 [Msiexec.exe - Execute Local MSI file with an embedded DLL](tests/628fa796-76c5-44c3-93aa-b9d8214fd568.md)
  * T1219 [ScreenConnect Application Download and Install on Windows](tests/4a18cc4e-416f-4966-9a9d-75731c4684c0.md)
  * T1218.007 [Msiexec.exe - Execute Local MSI file with embedded VBScript](tests/8d73c7b0-c2b1-4ac1-881a-4aa644f76064.md)
* proc_creation_win_mstsc.yml
  * T1021.001 [RDP to Server](tests/7382a43e-f19c-46be-8f09-5c63af7d3e2b.md)
  * T1021.001 [RDP to DomainController](tests/355d4632-8cb9-449d-91ce-b566d0253d3e.md)
* proc_creation_win_net_enum.yml
  * T1016 [System Network Configuration Discovery (TrickBot Style)](tests/dafaf052-5508-402d-bf77-51e0700c02e2.md)
  * T1016 [Qakbot Recon](tests/121de5c6-5818-4868-b8a7-8fd07c455c1b.md)
  * T1018 [Remote System Discovery - net](tests/85321a9c-897f-4a60-9f20-29788e50bccd.md)
* proc_creation_win_net_user_add.yml
  * T1136.002 [Create a new account similar to ANONYMOUS LOGON](tests/dc7726d2-8ccb-4cc6-af22-0d5afb53a548.md)
  * T1136.002 [Create a new Windows domain admin user](tests/fcec2963-9951-4173-9bfa-98d8b7834e62.md)
  * T1136.001 [Create a new user in a command prompt](tests/6657864e-0323-4206-9344-ac9cd7265a4f.md)
  * T1078.003 [Create local account with admin privileges](tests/a524ce99-86de-4db6-b4f9-e08f35a47a15.md)
  * T1078.001 [Enable Guest account with RDP capability and admin privileges](tests/99747561-ed8d-47f2-9c91-1e5fde1ed6e0.md)
  * T1564 [Create a Hidden User Called "$"](tests/2ec63cc2-4975-41a6-bf09-dffdfb610778.md)
  * T1136.001 [Create a new Windows admin user](tests/fda74566-a604-4581-a4cc-fbbe21d66559.md)
* proc_creation_win_netcat_execution.yml
  * T1095 [Netcat C2](tests/bcf0d1c1-3f6a-4847-b1c9-7ed4ea321f37.md)
* proc_creation_win_netsh_allow_port_rdp.yml
  * T1562.004 [Open a local port through Windows Firewall to any profile](tests/9636dd6e-7599-40d2-8eee-ac16434f35ed.md)
* proc_creation_win_netsh_fw_add.yml
  * T1562.004 [Allow Executable Through Firewall Located in Non-Standard Location](tests/6f5822d2-d38d-4f48-9bfc-916607ff6b8c.md)
  * T1021.001 [Changing RDP Port to Non Standard Port via Command_Prompt](tests/74ace21e-a31c-4f7d-b540-53e4eb6d1f73.md)
  * T1562.004 [Opening ports for proxy - HARDRAIN](tests/15e57006-79dd-46df-9bf9-31bc24fb5a80.md)
  * T1562.004 [Open a local port through Windows Firewall to any profile](tests/9636dd6e-7599-40d2-8eee-ac16434f35ed.md)
* proc_creation_win_netsh_fw_enable_group_rule.yml
  * T1562.004 [Allow SMB and RDP on Microsoft Defender Firewall](tests/d9841bf8-f161-4c73-81e9-fd773a5ff8c1.md)
* proc_creation_win_netsh_packet_capture.yml
  * T1040 [Windows Internal Packet Capture](tests/b5656f67-d67f-4de8-8e62-b5581630f528.md)
* proc_creation_win_netsh_port_fwd.yml
  * T1090.001 [portproxy reg key](tests/b8223ea9-4be2-44a6-b50a-9657a3d4e72a.md)
* proc_creation_win_network_scan_loop.yml
  * T1018 [Remote System Discovery - ping sweep](tests/6db1f57f-d1d5-4223-8a66-55c9c65a9592.md)
  * T1018 [Remote System Discovery - nslookup](tests/baa01aaa-5e13-45ec-8a0d-e46c93c9760f.md)
* proc_creation_win_network_sniffing.yml
  * T1040 [Packet Capture Windows Command Prompt](tests/a5b2f6a0-24b4-493e-9590-c699f75723ca.md)
* proc_creation_win_new_service_creation.yml
  * T1036.004 [Creating W32Time similar named service using sc](tests/b721c6ef-472c-4263-a0d9-37f1f4ecff66.md)
  * T1564.006 [Register Portable Virtualbox](tests/c59f246a-34f8-4e4d-9276-c295ef9ba0dd.md)
  * T1543.003 [Service Installation PowerShell](tests/491a4af6-a521-4b74-b23b-f7b3f1ee9e77.md)
  * T1543.003 [TinyTurla backdoor service w64time](tests/ef0581fd-528e-4662-87bc-4c2affb86940.md)
  * T1563.002 [RDP hijacking](tests/a37ac520-b911-458e-8aed-c5f1576d9f46.md)
  * T1543.003 [Service Installation CMD](tests/981e2942-e433-44e9-afc1-8c957a1496b6.md)
  * T1219 [RemotePC Software Execution](tests/fbff3f1f-b0bf-448e-840f-7e1687affdce.md)
  * T1574.009 [Execution of program.exe as service with unquoted service path](tests/2770dea7-c50f-457b-84c4-c40a47460d9f.md)
  * T1569.002 [Execute a Command as a Service](tests/2382dee2-a75f-49aa-9378-f52df6ed3fb1.md)
* proc_creation_win_nltest_recon.yml
  * T1016 [System Network Configuration Discovery (TrickBot Style)](tests/dafaf052-5508-402d-bf77-51e0700c02e2.md)
  * T1018 [Remote System Discovery - nltest](tests/52ab5108-3f6f-42fb-8ba3-73bc054f22c8.md)
* proc_creation_win_non_interactive_powershell.yml
  * T1218.005 [Mshta used to Execute PowerShell](tests/8707a805-2b76-4f32-b1c0-14e558205772.md)
  * T1105 [Windows - PowerShell Download](tests/42dc4460-9aa6-45d3-b1a6-3955d34e1fe8.md)
  * T1207 [DCShadow (Active Directory)](tests/0f4c5eb0-98a0-4496-9c3d-656b4f2bc8f6.md)
  * T1036.003 [File Extension Masquerading](tests/c7fa0c3b-b57f-4cba-9118-863bf4e653fc.md)
  * T1003.006 [Run DSInternals Get-ADReplAccount](tests/a0bced08-3fc5-4d8b-93b7-e8344739376e.md)
  * T1550.003 [Rubeus Kerberos Pass The Ticket](tests/a2fc4ec5-12c6-4fb4-b661-961f23f359cb.md)
  * T1562.006 [Disable Powershell ETW Provider - Windows](tests/6f118276-121d-4c09-bb58-a8fb4a72ee84.md)
  * T1204.002 [Office Generic Payload Download](tests/5202ee05-c420-4148-bf5e-fd7f7d24850c.md)
  * T1069.002 [Enumerate Active Directory Groups with Get-AdGroup](tests/3d1fcd2a-e51c-4cbe-8d84-9a843bad8dc8.md)
  * T1069.002 [Get-ADUser Enumeration using UserAccountControl flags (AS-REP Roasting)](tests/43fa81fb-34bb-4b5f-867b-03c7dbe0e3d8.md)
  * T1059.001 [Invoke-AppPathBypass](tests/06a220b6-7e29-4bd8-9d07-5b4d86742372.md)
  * T1027 [Obfuscated Command in PowerShell](tests/8b3f4ed6-077b-4bdd-891c-2d237f19410f.md)
  * T1003.001 [Dump LSASS.exe Memory using comsvcs.dll](tests/2536dee2-12fb-459a-8c37-971844fa73be.md)
  * T1557.001 [LLMNR Poisoning with Inveigh (PowerShell)](tests/deecd55f-afe0-4a62-9fba-4d1ba2deb321.md)
  * T1558.002 [Crafting Active Directory silver tickets with mimikatz](tests/385e59aa-113e-4711-84d9-f637aef01f2c.md)
  * T1216 [SyncAppvPublishingServer Signed Script PowerShell Command Execution](tests/275d963d-3f36-476c-8bef-a2a3960ee6eb.md)
  * T1615 [Get-DomainGPO to display group policy information via PowerView](tests/4e524c4e-0e02-49aa-8df5-93f3f7959b9f.md)
  * T1218.007 [Msiexec.exe - Execute Remote MSI file](tests/44a4bedf-ffe3-452e-bee4-6925ab125662.md)
  * T1547.001 [SystemBC Malware-as-a-Service Registry](tests/9dc7767b-30c1-4cc4-b999-50cab5e27891.md)
  * T1559.002 [Execute PowerShell script via Word DDE](tests/47c21fb6-085e-4b0d-b4d2-26d72c3830b3.md)
  * T1550.002 [Invoke-WMIExec Pass the Hash](tests/f8757545-b00a-4e4e-8cfb-8cfb961ee713.md)
  * T1218.005 [Mshta executes VBScript to execute malicious command](tests/906865c3-e05f-4acc-85c4-fbc185455095.md)
  * T1018 [Get-DomainController with PowerView](tests/b9d2e8ca-5520-4737-8076-4f08913da2c4.md)
  * T1087.002 [Get-DomainUser with PowerView](tests/93662494-5ed7-4454-a04c-8c8372808ac2.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
  * T1069.002 [Get-DomainGroup with PowerView](tests/5a8a181c-2c8e-478d-a943-549305a01230.md)
* proc_creation_win_office_shell.yml
  * T1204.002 [OSTAP JS version](tests/add560ef-20d6-4011-a937-2c340f930911.md)
  * T1204.002 [Office launching .bat file from AppData](tests/9215ea92-1ded-41b7-9cd6-79f9a78397aa.md)
  * T1204.002 [Headless Chrome code execution via VBA](tests/a19ee671-ed98-4e9d-b19c-d1954a51585a.md)
  * T1204.002 [Maldoc choice flags command execution](tests/0330a5d2-a45a-4272-a9ee-e364411c4b18.md)
  * T1204.002 [Office Generic Payload Download](tests/5202ee05-c420-4148-bf5e-fd7f7d24850c.md)
  * T1204.002 [OSTap Style Macro Execution](tests/8bebc690-18c7-4549-bc98-210f7019efff.md)
  * T1559.002 [Execute PowerShell script via Word DDE](tests/47c21fb6-085e-4b0d-b4d2-26d72c3830b3.md)
  * T1055 [Shellcode execution via VBA](tests/1c91e740-1729-4329-b779-feba6e71d048.md)
  * T1059.005 [Encoded VBS code execution](tests/e8209d5f-e42d-45e6-9c2f-633ac4f1eefa.md)
* proc_creation_win_office_spawn_exe_from_users_directory.yml
  * T1564 [Extract binary files via VBA](tests/6afe288a-8a8b-4d33-a629-8d03ba9dad3a.md)
* proc_creation_win_possible_applocker_bypass.yml
  * T1127.001 [MSBuild Bypass Using Inline Tasks (VB)](tests/ab042179-c0c5-402f-9bc8-42741f5ce359.md)
  * T1218.004 [InstallUtil Uninstall method call - /U variant](tests/34428cfa-8e38-41e5-aff4-9e1f8f3a7b4b.md)
  * T1218.004 [InstallUtil Install method call](tests/9f9968a6-601a-46ca-b7b7-6d4fe0f98f0b.md)
  * T1218.004 [InstallUtil Uninstall method call - '/installtype=notransaction /action=uninstall' variant](tests/06d9deba-f732-48a8-af8e-bdd6e4d98c1d.md)
  * T1218.004 [InstallUtil HelpText method call](tests/5a683850-1145-4326-a0e5-e91ced3c6022.md)
  * T1127.001 [MSBuild Bypass Using Inline Tasks (C#)](tests/58742c0f-cb01-44cd-a60b-fb26e8871c93.md)
  * T1218.009 [Regasm Uninstall Method Call Test](tests/71bfbfac-60b1-4fc0-ac8b-2cedbbdcb112.md)
  * T1219 [RemotePC Software Execution](tests/fbff3f1f-b0bf-448e-840f-7e1687affdce.md)
  * T1218.004 [InstallUtil class constructor method call](tests/9b7a7cfc-dd2e-43f5-a885-c0a3c270dd93.md)
  * T1218.009 [Regsvcs Uninstall Method Call Test](tests/fd3c1c6a-02d2-4b72-82d9-71c527abb126.md)
* proc_creation_win_powershell_amsi_bypass.yml
  * T1562.001 [AMSI Bypass - AMSI InitFailed](tests/695eed40-e949-40e5-b306-b4031e4154bd.md)
* proc_creation_win_powershell_audio_capture.yml
  * T1123 [using device audio capture commandlet](tests/9c3ad250-b185-4444-b5a9-d69218a10c95.md)
* proc_creation_win_powershell_bitsjob.yml
  * T1197 [Bitsadmin Download (PowerShell)](tests/f63b8bc4-07e5-4112-acba-56f646f3f0bc.md)
* proc_creation_win_powershell_cmdline_special_characters.yml
  * T1207 [DCShadow (Active Directory)](tests/0f4c5eb0-98a0-4496-9c3d-656b4f2bc8f6.md)
  * T1204.002 [OSTAP JS version](tests/add560ef-20d6-4011-a937-2c340f930911.md)
  * T1204.002 [Excel 4 Macro](tests/4ea1fc97-8a46-4b4e-ba48-af43d2a98052.md)
  * T1087.002 [Enumerate Linked Policies In ADSISearcher Discovery](tests/7ab0205a-34e4-4a44-9b04-e1541d1a57be.md)
  * T1027 [Obfuscated Command in PowerShell](tests/8b3f4ed6-077b-4bdd-891c-2d237f19410f.md)
  * T1562.001 [Uninstall Crowdstrike Falcon on Windows](tests/b32b1ccf-f7c1-49bc-9ddd-7d7466a7b297.md)
  * T1087.002 [Enumerate Root Domain linked policies Discovery](tests/00c652e2-0750-4ca6-82ff-0204684a6fe4.md)
  * T1059.001 [Mimikatz - Cradlecraft PsSendKeys](tests/af1800cf-9f9d-4fd1-a709-14b1e6de020d.md)
  * T1218.009 [Regsvcs Uninstall Method Call Test](tests/fd3c1c6a-02d2-4b72-82d9-71c527abb126.md)
* proc_creation_win_powershell_cmdline_specific_comb_methods.yml
  * T1136.002 [Create a new Domain Account using PowerShell](tests/5a3497a4-1568-4663-b12a-d4a5ed70c7d7.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Remote](tests/cab413d8-9e4a-4b8d-9b84-c985bd73a442.md)
  * T1059.001 [Obfuscation Tests](tests/4297c41a-8168-4138-972d-01f3ee92c804.md)
* proc_creation_win_powershell_defender_exclusion.yml
  * T1562.001 [Tamper with Windows Defender Evade Scanning -Extension](tests/315f4be6-2240-4552-b3e1-d1047f5eecea.md)
  * T1562.001 [Tamper with Windows Defender Evade Scanning -Process](tests/a123ce6a-3916-45d6-ba9c-7d4081315c27.md)
  * T1562.001 [Tamper with Windows Defender Evade Scanning -Folder](tests/0b19f4ee-de90-4059-88cb-63c800c683ed.md)
* proc_creation_win_powershell_disable_windef_av.yml
  * T1562.001 [Tamper with Windows Defender Command Prompt](tests/aa875ed4-8935-47e2-b2c5-6ec00ab220d2.md)
  * T1562.001 [Disable Defender Using NirSoft AdvancedRun](tests/81ce22fd-9612-4154-918e-8a1f285d214d.md)
* proc_creation_win_powershell_downgrade_attack.yml
  * T1059.001 [PowerShell Downgrade Attack](tests/9148e7c4-9356-420e-a416-e896e9c0f73e.md)
* proc_creation_win_powershell_download.yml
  * T1105 [Windows - PowerShell Download](tests/42dc4460-9aa6-45d3-b1a6-3955d34e1fe8.md)
  * T1095 [Powercat C2](tests/3e0e0e7f-6aa2-4a61-b61d-526c2cc9330e.md)
  * T1059.001 [Run Bloodhound from Memory using Download Cradle](tests/bf8c1441-4674-4dab-8e4e-39d93d08f9b7.md)
  * T1095 [ICMP C2](tests/0268e63c-e244-42db-bef7-72a9e59fc1fc.md)
  * T1071.004 [DNS C2](tests/e7bf9802-2e78-4db9-93b5-181b7bcd37d7.md)
  * T1059.001 [Invoke-AppPathBypass](tests/06a220b6-7e29-4bd8-9d07-5b4d86742372.md)
  * T1105 [File Download via PowerShell](tests/54a4daf1-71df-4383-9ba7-f1a295d8b6d2.md)
  * T1615 [Get-DomainGPO to display group policy information via PowerView](tests/4e524c4e-0e02-49aa-8df5-93f3f7959b9f.md)
  * T1547.001 [PowerShell Registry RunOnce](tests/eb44f842-0457-4ddc-9b92-c4caa144ac42.md)
  * T1059.001 [Obfuscation Tests](tests/4297c41a-8168-4138-972d-01f3ee92c804.md)
* proc_creation_win_powershell_download_patterns.yml
  * T1615 [Get-DomainGPO to display group policy information via PowerView](tests/4e524c4e-0e02-49aa-8df5-93f3f7959b9f.md)
* proc_creation_win_powershell_frombase64string.yml
  * T1027 [Execute base64-encoded PowerShell from Windows Registry](tests/450e7218-7915-4be4-8b9b-464a49eafcec.md)
  * T1059.001 [PowerShell Fileless Script Execution](tests/fa050f5e-bc75-4230-af73-b6fd7852cd73.md)
  * T1053.005 [Scheduled Task Executing Base64 Encoded Commands From Registry](tests/e895677d-4f06-49ab-91b6-ae3742d0a2ba.md)
  * T1218.009 [Regsvcs Uninstall Method Call Test](tests/fd3c1c6a-02d2-4b72-82d9-71c527abb126.md)
* proc_creation_win_powershell_reverse_shell_connection.yml
  * T1016 [List Open Egress Ports](tests/4b467538-f102-491d-ace7-ed487b853bf5.md)
* proc_creation_win_powershell_suspicious_parameter_variation.yml
  * T1615 [Get-DomainGPO to display group policy information via PowerView](tests/4e524c4e-0e02-49aa-8df5-93f3f7959b9f.md)
  * T1059.001 [Obfuscation Tests](tests/4297c41a-8168-4138-972d-01f3ee92c804.md)
* proc_creation_win_powershell_xor_commandline.yml
  * T1027 [Obfuscated Command in PowerShell](tests/8b3f4ed6-077b-4bdd-891c-2d237f19410f.md)
  * T1132.001 [XOR Encoded data.](tests/c3ed6d2a-e3ad-400d-ad78-bbfdbfeacc08.md)
  * T1059.001 [Obfuscation Tests](tests/4297c41a-8168-4138-972d-01f3ee92c804.md)
* proc_creation_win_proc_dump_createdump.yml
  * T1003.001 [Dump LSASS with .Net 5 createdump.exe](tests/9d0072c8-7cca-45c4-bd14-f852cfa35cf0.md)
* proc_creation_win_procdump.yml
  * T1003.001 [Dump LSASS.exe Memory using ProcDump](tests/0be2230c-9ab3-4ac2-8826-3199b9a0ebf8.md)
  * T1003.001 [Create Mini Dump of LSASS.exe using ProcDump](tests/7cede33f-0acd-44ef-9774-15511300b24b.md)
* proc_creation_win_protocolhandler_suspicious_file.yml
  * T1218 [ProtocolHandler.exe Downloaded a Suspicious File](tests/db020456-125b-4c8b-a4a7-487df8afb5a2.md)
* proc_creation_win_proxy_execution_wuauclt.yml
  * T1218 [Load Arbitrary DLL via Wuauclt (Windows Update Client)](tests/49fbd548-49e9-4bb7-94a6-3769613912b8.md)
* proc_creation_win_psexesvc_start.yml
  * T1207 [DCShadow (Active Directory)](tests/0f4c5eb0-98a0-4496-9c3d-656b4f2bc8f6.md)
  * T1550.003 [Rubeus Kerberos Pass The Ticket](tests/a2fc4ec5-12c6-4fb4-b661-961f23f359cb.md)
  * T1562.006 [Disable Powershell ETW Provider - Windows](tests/6f118276-121d-4c09-bb58-a8fb4a72ee84.md)
  * T1003.004 [Dumping LSA Secrets](tests/55295ab0-a703-433b-9ca4-ae13807de12f.md)
  * T1021.002 [Copy and Execute File with PsExec](tests/0eb03d41-79e4-4393-8e57-6344856be1cf.md)
  * T1569.002 [Use PsExec to execute a command on a remote host](tests/873106b7-cfed-454b-8680-fa9f6400431c.md)
* proc_creation_win_pypykatz.yml
  * T1003.002 [Registry parse with pypykatz](tests/a96872b2-cbf3-46cf-8eb4-27e8c0e85263.md)
* proc_creation_win_query_registry.yml
  * T1012 [Query Registry](tests/8f7578c4-9863-4d83-875c-a565573bbdf0.md)
  * T1082 [System Information Discovery](tests/66703791-c902-4560-8770-42b8a91f7667.md)
* proc_creation_win_ransom_blackbyte.yml
  * T1059.003 [Simulate BlackByte Ransomware Print Bombing](tests/6b2903ac-8f36-450d-9ad5-b220e8a2dcb9.md)
* proc_creation_win_redirect_to_stream.yml
  * T1564.004 [Create ADS command prompt](tests/17e7637a-ddaf-4a82-8622-377e20de8fdb.md)
* proc_creation_win_reg_add_run_key.yml
  * T1547.001 [Reg Key Run](tests/e55be3fd-3521-4610-9d1a-e210e42dcf05.md)
  * T1112 [Modify Registry of Local Machine - cmd](tests/282f929a-6bc5-42b8-bd93-960c3ba35afe.md)
  * T1547.001 [Reg Key RunOnce](tests/554cbd88-cde1-4b56-8168-0be552eed9eb.md)
* proc_creation_win_reg_dump_sam.yml
  * T1003.002 [Registry dump of SAM, creds, and secrets](tests/5c2571d0-1572-416d-9676-812e64ca9f44.md)
* proc_creation_win_reg_service_imagepath_change.yml
  * T1574.011 [Service ImagePath Change with reg.exe](tests/f38e9eea-e1d7-4ba6-b716-584791963827.md)
* proc_creation_win_regedit_export_keys.yml
  * T1564.004 [Alternate Data Streams (ADS)](tests/8822c3b0-d9f9-4daf-a043-49f4602364f4.md)
* proc_creation_win_regedit_import_keys.yml
  * T1219 [RemotePC Software Execution](tests/fbff3f1f-b0bf-448e-840f-7e1687affdce.md)
* proc_creation_win_remote_powershell_session_process.yml
  * T1021.006 [Invoke-Command](tests/5295bd61-bd7e-4744-9d52-85962a4cf2d6.md)
  * T1059.001 [PowerShell Session Creation and Use](tests/7c1acec2-78fa-4305-a3e0-db2a54cddecd.md)
* proc_creation_win_remote_time_discovery.yml
  * T1124 [System Time Discovery](tests/20aba24b-e61f-4b26-b4ce-4784f763ca20.md)
  * T1105 [certutil download (verifyctl)](tests/ffd492e3-0455-4518-9fb1-46527c9f241b.md)
  * T1124 [System Time Discovery - PowerShell](tests/1d5711d6-655c-4a47-ae9c-6503c74fa877.md)
  * T1059.001 [Powershell invoke mshta.exe download](tests/8a2ad40b-12c7-4b25-8521-2737b0a415af.md)
* proc_creation_win_remove_windows_defender_definition_files.yml
  * T1562.001 [Remove Windows Defender Definition Files](tests/3d47daaa-2f56-43e0-94cc-caf5d8d52a68.md)
* proc_creation_win_renamed_binary.yml
  * T1036.003 [Masquerading - windows exe running as different windows exe](tests/c3d24a39-2bfe-4c6a-b064-90cd73896cb0.md)
  * T1036.003 [Malicious process Masquerading as LSM.exe](tests/83810c46-f45e-4485-9ab6-8ed0e9e6ed7f.md)
  * T1036.003 [Masquerading as Windows LSASS process](tests/5ba5a3d1-cf3c-4499-968a-a93155d1f717.md)
  * T1036.003 [Masquerading - powershell.exe running as taskhostw.exe](tests/ac9d0fc3-8aa8-4ab5-b11f-682cd63b40aa.md)
  * T1036.003 [Masquerading - wscript.exe running as svchost.exe](tests/24136435-c91a-4ede-9da1-8b284a1c1a23.md)
  * T1140 [Certutil Rename and Decode](tests/71abc534-3c05-4d0c-80f7-cbe93cb2aa94.md)
  * T1036.003 [Masquerading - cscript.exe running as notepad.exe](tests/3a2a578b-0a01-46e4-92e3-62e2859b42f0.md)
  * T1105 [svchost writing a file to a UNC path](tests/fa5a2759-41d7-4e13-a19c-e8f28a53566f.md)
* proc_creation_win_renamed_binary_highly_relevant.yml
  * T1036.003 [Masquerading - powershell.exe running as taskhostw.exe](tests/ac9d0fc3-8aa8-4ab5-b11f-682cd63b40aa.md)
  * T1036.003 [Masquerading - wscript.exe running as svchost.exe](tests/24136435-c91a-4ede-9da1-8b284a1c1a23.md)
  * T1140 [Certutil Rename and Decode](tests/71abc534-3c05-4d0c-80f7-cbe93cb2aa94.md)
  * T1036.003 [Masquerading - cscript.exe running as notepad.exe](tests/3a2a578b-0a01-46e4-92e3-62e2859b42f0.md)
* proc_creation_win_renamed_powershell.yml
  * T1036.003 [Masquerading - powershell.exe running as taskhostw.exe](tests/ac9d0fc3-8aa8-4ab5-b11f-682cd63b40aa.md)
* proc_creation_win_renamed_procdump.yml
  * T1003.001 [Dump LSASS.exe Memory using ProcDump](tests/0be2230c-9ab3-4ac2-8826-3199b9a0ebf8.md)
* proc_creation_win_root_certificate_installed.yml
  * T1553.004 [Install root CA on Windows with certutil](tests/5fdb1a7a-a93c-4fbe-aa29-ddd9ef94ed1f.md)
* proc_creation_win_run_executable_invalid_extension.yml
  * T1218.011 [Rundll32 execute JavaScript Remote Payload With GetObject](tests/cf3bdb9a-dd11-4b6c-b0d0-9e22b68a71be.md)
  * T1218.011 [Execution of non-dll using rundll32.exe](tests/ae3a8605-b26e-457c-b6b3-2702fd335bac.md)
  * T1218.011 [Rundll32 with desk.cpl](tests/83a95136-a496-423c-81d3-1c6750133917.md)
  * T1218.011 [Rundll32 execute VBscript command](tests/638730e7-7aed-43dc-bf8c-8117f805f5bb.md)
  * T1546.015 [COM Hijacking - InprocServer32](tests/48117158-d7be-441b-bc6a-d9e36e47b52b.md)
  * T1219 [ScreenConnect Application Download and Install on Windows](tests/4a18cc4e-416f-4966-9a9d-75731c4684c0.md)
* proc_creation_win_run_from_zip.yml
  * T1027 [Execution from Compressed File](tests/f8c8a909-5f29-49ac-9244-413936ce6d1f.md)
* proc_creation_win_run_powershell_script_from_ads.yml
  * T1059.001 [NTFS Alternate Data Stream Access](tests/8e5c5532-1181-4c1d-bb79-b3a9f5dbd680.md)
* proc_creation_win_run_virtualbox.yml
  * T1564.006 [Register Portable Virtualbox](tests/c59f246a-34f8-4e4d-9276-c295ef9ba0dd.md)
  * T1564.006 [Create and start VirtualBox virtual machine](tests/88b81702-a1c0-49a9-95b2-2dd53d755767.md)
* proc_creation_win_rundll32_installscreensaver.yml
  * T1218.011 [Rundll32 with desk.cpl](tests/83a95136-a496-423c-81d3-1c6750133917.md)
* proc_creation_win_rundll32_registered_com_objects.yml
  * T1546.015 [COM Hijacking - InprocServer32](tests/48117158-d7be-441b-bc6a-d9e36e47b52b.md)
* proc_creation_win_sdbinst_shim_persistence.yml
  * T1546.011 [Application Shim Installation](tests/9ab27e22-ee62-4211-962b-d36d9a0e6a18.md)
* proc_creation_win_sdclt_child_process.yml
  * T1059.001 [Invoke-AppPathBypass](tests/06a220b6-7e29-4bd8-9d07-5b4d86742372.md)
  * T1548.002 [Bypass UAC using sdclt DelegateExecute](tests/3be891eb-4608-4173-87e8-78b494c029b7.md)
* proc_creation_win_sdelete.yml
  * T1485 [Windows - Overwrite file with Sysinternals SDelete](tests/476419b5-aebf-4366-a131-ae3e8dae5fc2.md)
* proc_creation_win_service_execution.yml
  * T1007 [System Service Discovery - net.exe](tests/5f864a3f-8ce9-45c0-812c-bdf7d8aeacc3.md)
  * T1563.002 [RDP hijacking](tests/a37ac520-b911-458e-8aed-c5f1576d9f46.md)
* proc_creation_win_service_stop.yml
  * T1489 [Windows - Stop service using Service Controller](tests/21dfb440-830d-4c86-a3e5-2a491d5a8d04.md)
  * T1562.001 [Disable Arbitrary Security Windows Service](tests/a1230893-56ac-4c81-b644-2108e982f8f5.md)
  * T1489 [Windows - Stop service using net.exe](tests/41274289-ec9c-4213-bea4-e43c4aa57954.md)
  * T1562.001 [Tamper with Windows Defender Command Prompt](tests/aa875ed4-8935-47e2-b2c5-6ec00ab220d2.md)
* proc_creation_win_set_policies_to_unsecure_level.yml
  * T1216 [SyncAppvPublishingServer Signed Script PowerShell Command Execution](tests/275d963d-3f36-476c-8bef-a2a3960ee6eb.md)
  * T1615 [Get-DomainGPO to display group policy information via PowerView](tests/4e524c4e-0e02-49aa-8df5-93f3f7959b9f.md)
  * T1112 [Change Powershell Execution Policy to Bypass](tests/f3a6cceb-06c9-48e5-8df8-8867a6814245.md)
  * T1547.001 [SystemBC Malware-as-a-Service Registry](tests/9dc7767b-30c1-4cc4-b999-50cab5e27891.md)
* proc_creation_win_shadow_copies_access_symlink.yml
  * T1003.003 [Create Symlink to Volume Shadow Copy](tests/21748c28-2793-4284-9e07-d6d028b66702.md)
* proc_creation_win_shadow_copies_creation.yml
  * T1003.003 [Create Volume Shadow Copy remotely with WMI](tests/d893459f-71f0-484d-9808-ec83b2b64226.md)
  * T1003.003 [Create Symlink to Volume Shadow Copy](tests/21748c28-2793-4284-9e07-d6d028b66702.md)
  * T1003.003 [Create Volume Shadow Copy with WMI](tests/224f7de0-8f0a-4a94-b5d8-989b036c86da.md)
  * T1003.003 [Create Volume Shadow Copy with vssadmin](tests/dcebead7-6c28-4b4b-bf3c-79deb1b1fc7f.md)
* proc_creation_win_shadow_copies_deletion.yml
  * T1207 [DCShadow (Active Directory)](tests/0f4c5eb0-98a0-4496-9c3d-656b4f2bc8f6.md)
  * T1490 [Windows - Delete Volume Shadow Copies](tests/43819286-91a9-4369-90ed-d31fb4da2c01.md)
  * T1490 [Windows - Delete Volume Shadow Copies via WMI](tests/6a3ff8dd-f49c-4272-a658-11c2fe58bd88.md)
  * T1490 [Windows - wbadmin Delete Windows Backup Catalog](tests/263ba6cb-ea2b-41c9-9d4e-b652dadd002c.md)
* proc_creation_win_shell_spawn_mshta.yml
  * T1218.005 [Mshta used to Execute PowerShell](tests/8707a805-2b76-4f32-b1c0-14e558205772.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement](tests/007e5672-2088-4853-a562-7490ddc19447.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
  * T1218.005 [Mshta Executes Remote HTML Application (HTA)](tests/c4b97eeb-5249-4455-a607-59f95485cb45.md)
  * T1218.005 [Mshta executes VBScript to execute malicious command](tests/906865c3-e05f-4acc-85c4-fbc185455095.md)
  * T1059.001 [Powershell invoke mshta.exe download](tests/8a2ad40b-12c7-4b25-8521-2737b0a415af.md)
* proc_creation_win_shell_spawn_susp_program.yml
  * T1105 [certutil download (verifyctl)](tests/ffd492e3-0455-4518-9fb1-46527c9f241b.md)
  * T1218.005 [Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md)
  * T1003.002 [dump volume shadow copy hives with certutil](tests/eeb9751a-d598-42d3-b11c-c122d9c3f6c7.md)
  * T1071.004 [DNS C2](tests/e7bf9802-2e78-4db9-93b5-181b7bcd37d7.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1553.004 [Install root CA on Windows with certutil](tests/5fdb1a7a-a93c-4fbe-aa29-ddd9ef94ed1f.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
  * T1218.005 [Mshta Executes Remote HTML Application (HTA)](tests/c4b97eeb-5249-4455-a607-59f95485cb45.md)
* proc_creation_win_software_discovery.yml
  * T1518 [Find and Display Internet Explorer Browser Version](tests/68981660-6670-47ee-a5fa-7e74806420a4.md)
* proc_creation_win_spn_enum.yml
  * T1558.003 [Request All Tickets via PowerShell](tests/902f4ed2-1aba-4133-90f2-cff6d299d6da.md)
  * T1558.003 [Extract all accounts in use as SPN using setspn](tests/e6f4affd-d826-4871-9a62-6c9004b8fe06.md)
* proc_creation_win_sqlite_firefox_cookies.yml
  * T1539 [Steal Firefox Cookies (Windows)](tests/4b437357-f4e9-4c84-9fa6-9bcee6f826aa.md)
* proc_creation_win_sus_auditpol_usage.yml
  * T1562.002 [Clear Windows Audit Policy Config](tests/913c0e4e-4b37-4b78-ad0b-90e7b25010f6.md)
  * T1562.002 [Impair Windows Audit Log Policy](tests/5102a3a7-e2d7-4129-9e45-f483f2e0eea8.md)
* proc_creation_win_susp_7z.yml
  * T1560.001 [Compress Data and lock with password for Exfiltration with 7zip](tests/d1334303-59cb-4a03-8313-b3e24d02c198.md)
* proc_creation_win_susp_add_user_remote_desktop.yml
  * T1078.001 [Enable Guest account with RDP capability and admin privileges](tests/99747561-ed8d-47f2-9c91-1e5fde1ed6e0.md)
* proc_creation_win_susp_adfind.yml
  * T1018 [Adfind - Enumerate Active Directory Computer Objects](tests/a889f5be-2d54-4050-bd05-884578748bb4.md)
  * T1016 [Adfind - Enumerate Active Directory Subnet Objects](tests/9bb45dd7-c466-4f93-83a1-be30e56033ee.md)
  * T1069.002 [Adfind - Query Active Directory Groups](tests/48ddc687-82af-40b7-8472-ff1e742e8274.md)
  * T1482 [Adfind - Enumerate Active Directory Trusts](tests/15fe436d-e771-4ff3-b655-2dca9ba52834.md)
  * T1018 [Adfind - Enumerate Active Directory Domain Controller Objects](tests/5838c31e-a0e2-4b9f-b60a-d79d2cb7995e.md)
  * T1482 [Adfind - Enumerate Active Directory OUs](tests/d1c73b96-ab87-4031-bad8-0e1b3b8bf3ec.md)
  * T1087.002 [Adfind - Enumerate Active Directory User Objects](tests/e1ec8d20-509a-4b9a-b820-06c9b2da8eb7.md)
* proc_creation_win_susp_adfind_enumerate.yml
  * T1087.002 [Adfind - Enumerate Active Directory Admins](tests/b95fd967-4e62-4109-b48d-265edfd28c3a.md)
  * T1087.002 [Adfind - Enumerate Active Directory Exchange AD Objects](tests/5e2938fb-f919-47b6-8b29-2f6a1f718e99.md)
  * T1087.002 [Adfind -Listing password policy](tests/736b4f53-f400-4c22-855d-1a6b5a551600.md)
* proc_creation_win_susp_adidnsdump.yml
  * T1018 [Remote System Discovery - adidnsdump](tests/95e19466-469e-4316-86d2-1dc401b5a959.md)
* proc_creation_win_susp_advancedrun.yml
  * T1562.001 [Disable Defender Using NirSoft AdvancedRun](tests/81ce22fd-9612-4154-918e-8a1f285d214d.md)
* proc_creation_win_susp_advancedrun_priv_user.yml
  * T1562.001 [Disable Defender Using NirSoft AdvancedRun](tests/81ce22fd-9612-4154-918e-8a1f285d214d.md)
* proc_creation_win_susp_athremotefxvgpudisablementcommand.yml
  * T1218 [Invoke-ATHRemoteFXvGPUDisablementCommand base test](tests/9ebe7901-7edf-45c0-b5c7-8366300919db.md)
* proc_creation_win_susp_calc.yml
  * T1036.003 [File Extension Masquerading](tests/c7fa0c3b-b57f-4cba-9118-863bf4e653fc.md)
  * T1547.005 [Modify SSP configuration in registry](tests/afdfd7e3-8a0b-409f-85f7-886fdf249c9e.md)
  * T1140 [Deobfuscate/Decode Files Or Information](tests/dc6fe391-69e6-4506-bd06-ea5eeb4082f8.md)
  * T1140 [Certutil Rename and Decode](tests/71abc534-3c05-4d0c-80f7-cbe93cb2aa94.md)
  * T1216 [manage-bde.wsf Signed Script Command Execution](tests/2a8f2d3c-3dec-4262-99dd-150cb2a4d63a.md)
  * T1218.011 [Rundll32 with desk.cpl](tests/83a95136-a496-423c-81d3-1c6750133917.md)
  * T1202 [Indirect Command Execution - pcalua.exe](tests/cecfea7a-5f03-4cdd-8bc8-6f7c22862440.md)
* proc_creation_win_susp_certutil_command.yml
  * T1105 [certutil download (verifyctl)](tests/ffd492e3-0455-4518-9fb1-46527c9f241b.md)
  * T1140 [Deobfuscate/Decode Files Or Information](tests/dc6fe391-69e6-4506-bd06-ea5eeb4082f8.md)
  * T1105 [certutil download (urlcache)](tests/dd3b61dd-7bbc-48cd-ab51-49ad1a776df0.md)
  * T1564.004 [Alternate Data Streams (ADS)](tests/8822c3b0-d9f9-4daf-a043-49f4602364f4.md)
  * T1140 [Certutil Rename and Decode](tests/71abc534-3c05-4d0c-80f7-cbe93cb2aa94.md)
* proc_creation_win_susp_certutil_encode.yml
  * T1003.002 [dump volume shadow copy hives with certutil](tests/eeb9751a-d598-42d3-b11c-c122d9c3f6c7.md)
* proc_creation_win_susp_char_in_cmd.yml
  * T1027 [Obfuscated Command Line using special Unicode characters](tests/e68b945c-52d0-4dd9-a5e8-d173d70c448f.md)
* proc_creation_win_susp_cipher.yml
  * T1485 [Overwrite deleted data on C drive](tests/321fd25e-0007-417f-adec-33232252be19.md)
* proc_creation_win_susp_cmd_shadowcopy_access.yml
  * T1003.003 [Copy NTDS.dit from Volume Shadow Copy](tests/c6237146-9ea6-4711-85c9-c56d263a6b03.md)
* proc_creation_win_susp_cmdl32_lolbas.yml
  * T1105 [Download a file with Microsoft Connection Manager Auto-Download](tests/d239772b-88e2-4a2e-8473-897503401bcc.md)
* proc_creation_win_susp_codepage_lookup.yml
  * T1614.001 [Discover System Language by Registry Query](tests/631d4cf1-42c9-4209-8fe9-6bd4de9421be.md)
* proc_creation_win_susp_compression_params.yml
  * T1560.001 [Compress Data and lock with password for Exfiltration with 7zip](tests/d1334303-59cb-4a03-8313-b3e24d02c198.md)
* proc_creation_win_susp_comsvcs_procdump.yml
  * T1003.001 [Dump LSASS.exe Memory using comsvcs.dll](tests/2536dee2-12fb-459a-8c37-971844fa73be.md)
  * T1003 [Dump svchost.exe to gather RDP credentials](tests/d400090a-d8ca-4be0-982e-c70598a23de9.md)
* proc_creation_win_susp_conhost.yml
  * T1202 [Indirect Command Execution - conhost.exe](tests/cf3391e0-b482-4b02-87fc-ca8362269b29.md)
* proc_creation_win_susp_copy_lateral_movement.yml
  * T1003.002 [dump volume shadow copy hives with certutil](tests/eeb9751a-d598-42d3-b11c-c122d9c3f6c7.md)
  * T1039 [Copy a sensitive File over Administive share with Powershell](tests/7762e120-5879-44ff-97f8-008b401b9a98.md)
  * T1039 [Copy a sensitive File over Administive share with copy](tests/6ed67921-1774-44ba-bac6-adb51ed60660.md)
  * T1105 [svchost writing a file to a UNC path](tests/fa5a2759-41d7-4e13-a19c-e8f28a53566f.md)
  * T1003.002 [dump volume shadow copy hives with System.IO.File](tests/9d77fed7-05f8-476e-a81b-8ff0472c64d0.md)
* proc_creation_win_susp_copy_system32.yml
  * T1036.003 [File Extension Masquerading](tests/c7fa0c3b-b57f-4cba-9118-863bf4e653fc.md)
  * T1546.002 [Set Arbitrary Binary as Screensaver](tests/281201e7-de41-4dc9-b73d-f288938cbb64.md)
  * T1036.003 [Malicious process Masquerading as LSM.exe](tests/83810c46-f45e-4485-9ab6-8ed0e9e6ed7f.md)
  * T1036.003 [Masquerading as Windows LSASS process](tests/5ba5a3d1-cf3c-4499-968a-a93155d1f717.md)
  * T1036 [System File Copied to Unusual Location](tests/51005ac7-52e2-45e0-bdab-d17c6d4916cd.md)
  * T1546.008 [Replace binary of sticky keys](tests/934e90cf-29ca-48b3-863c-411737ad44e3.md)
  * T1036.003 [Masquerading - powershell.exe running as taskhostw.exe](tests/ac9d0fc3-8aa8-4ab5-b11f-682cd63b40aa.md)
  * T1036.003 [Masquerading - wscript.exe running as svchost.exe](tests/24136435-c91a-4ede-9da1-8b284a1c1a23.md)
  * T1140 [Certutil Rename and Decode](tests/71abc534-3c05-4d0c-80f7-cbe93cb2aa94.md)
  * T1543.003 [TinyTurla backdoor service w64time](tests/ef0581fd-528e-4662-87bc-4c2affb86940.md)
  * T1218.011 [Rundll32 with desk.cpl](tests/83a95136-a496-423c-81d3-1c6750133917.md)
  * T1036.003 [Masquerading - cscript.exe running as notepad.exe](tests/3a2a578b-0a01-46e4-92e3-62e2859b42f0.md)
  * T1574.001 [DLL Search Order Hijacking - amsi.dll](tests/8549ad4b-b5df-4a2d-a3d7-2aee9e7052a3.md)
  * T1105 [svchost writing a file to a UNC path](tests/fa5a2759-41d7-4e13-a19c-e8f28a53566f.md)
  * T1548.002 [Bypass UAC by Mocking Trusted Directories](tests/f7a35090-6f7f-4f64-bb47-d657bf5b10c1.md)
  * T1003.003 [Copy NTDS.dit from Volume Shadow Copy](tests/c6237146-9ea6-4711-85c9-c56d263a6b03.md)
* proc_creation_win_susp_csc_folder.yml
  * T1218.005 [Invoke HTML Application - JScript Engine with Rundll32 and Inline Protocol Handler](tests/e7e3a525-7612-4d68-a5d3-c4649181b8af.md)
  * T1010 [List Process Main Windows - C# .NET](tests/fe94a1c3-3e22-4dc9-9fdf-3a8bdbc10dc4.md)
  * T1134.004 [Parent PID Spoofing using PowerShell](tests/069258f4-2162-46e9-9a25-c9c6c56150d2.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement](tests/007e5672-2088-4853-a562-7490ddc19447.md)
  * T1027.004 [Dynamic C# Compile](tests/453614d8-3ba6-4147-acc0-7ec4b3e1faef.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations](tests/686a9785-f99b-41d4-90df-66ed515f81d7.md)
  * T1036.005 [Masquerade as a built-in system executable](tests/35eb8d16-9820-4423-a2a1-90c4f5edd9ca.md)
  * T1218.005 [Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine Simulating Double Click](tests/58a193ec-131b-404e-b1ca-b35cf0b18c33.md)
  * T1134.002 [Access Token Manipulation](tests/dbf4f5a9-b8e0-46a3-9841-9ad71247239e.md)
  * T1071.004 [DNS C2](tests/e7bf9802-2e78-4db9-93b5-181b7bcd37d7.md)
  * T1218.004 [InstallUtil Uninstall method call - /U variant](tests/34428cfa-8e38-41e5-aff4-9e1f8f3a7b4b.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1218.004 [InstallUtil Install method call](tests/9f9968a6-601a-46ca-b7b7-6d4fe0f98f0b.md)
  * T1027.004 [Compile After Delivery using csc.exe](tests/ffcdbd6a-b0e8-487d-927a-09127fe9a206.md)
  * T1218.004 [InstallUtil Uninstall method call - '/installtype=notransaction /action=uninstall' variant](tests/06d9deba-f732-48a8-af8e-bdd6e4d98c1d.md)
  * T1218 [Invoke-ATHRemoteFXvGPUDisablementCommand base test](tests/9ebe7901-7edf-45c0-b5c7-8366300919db.md)
  * T1218.004 [InstallUtil HelpText method call](tests/5a683850-1145-4326-a0e5-e91ced3c6022.md)
  * T1127.001 [MSBuild Bypass Using Inline Tasks (C#)](tests/58742c0f-cb01-44cd-a60b-fb26e8871c93.md)
  * T1218.004 [InstallUtil evasive invocation](tests/559e6d06-bb42-4307-bff7-3b95a8254bad.md)
  * T1218.004 [CheckIfInstallable method call](tests/ffd9c807-d402-47d2-879d-f915cf2a3a94.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations](tests/86a43bad-12e3-4e85-b97c-4d5cf25b95c3.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments](tests/0d181431-ddf3-4826-8055-2dbf63ae848b.md)
  * T1134.004 [Parent PID Spoofing - Spawn from New Process](tests/2988133e-561c-4e42-a15f-6281e6a9b2db.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Local](tests/78e95057-d429-4e66-8f82-0f060c1ac96f.md)
  * T1218.009 [Regasm Uninstall Method Call Test](tests/71bfbfac-60b1-4fc0-ac8b-2cedbbdcb112.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Specified Process](tests/cbbff285-9051-444a-9d17-c07cd2d230eb.md)
  * T1218.004 [InstallHelper method call](tests/d43a5bde-ae28-4c55-a850-3f4c80573503.md)
  * T1552.004 [ADFS token signing and encryption certificates theft - Remote](tests/cab413d8-9e4a-4b8d-9b84-c985bd73a442.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
  * T1219 [ScreenConnect Application Download and Install on Windows](tests/4a18cc4e-416f-4966-9a9d-75731c4684c0.md)
  * T1134.004 [Parent PID Spoofing - Spawn from svchost.exe](tests/e9f2b777-3123-430b-805d-5cedc66ab591.md)
  * T1106 [Execution through API - CreateProcess](tests/99be2089-c52d-4a4a-b5c3-261ee42c8b62.md)
  * T1134.004 [Parent PID Spoofing - Spawn from Current Process](tests/14920ebd-1d61-491a-85e0-fe98efe37f25.md)
  * T1218.004 [InstallUtil class constructor method call](tests/9b7a7cfc-dd2e-43f5-a885-c0a3c270dd93.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments](tests/1c0a870f-dc74-49cf-9afc-eccc45e58790.md)
  * T1055.012 [Process Hollowing using PowerShell](tests/562427b4-39ef-4e8c-af88-463a78e70b9c.md)
  * T1218.009 [Regsvcs Uninstall Method Call Test](tests/fd3c1c6a-02d2-4b72-82d9-71c527abb126.md)
* proc_creation_win_susp_cscript_vbs.yml
  * T1059.005 [Visual Basic script execution to gather local computer information](tests/1620de42-160a-4fe5-bbaf-d3fef0181ce9.md)
  * T1082 [Griffon Recon](tests/69bd4abe-8759-49a6-8d21-0f15822d6370.md)
  * T1216.001 [PubPrn.vbs Signed Script Bypass](tests/9dd29a1f-1e16-4862-be83-913b10a88f6c.md)
* proc_creation_win_susp_curl_download.yml
  * T1105 [Curl Download File](tests/2b080b99-0deb-4d51-af0f-833d37c4ca6a.md)
* proc_creation_win_susp_curl_fileupload.yml
  * T1105 [Curl Upload File](tests/635c9a38-6cbf-47dc-8615-3810bc1167cf.md)
  * T1048.002 [Exfiltrate data HTTPS using curl windows](tests/1cdf2fb0-51b6-4fd8-96af-77020d5f1bf0.md)
* proc_creation_win_susp_curl_useragent.yml
  * T1071.001 [Malicious User Agents - CMD](tests/dc3488b0-08c7-4fea-b585-905c83b48180.md)
* proc_creation_win_susp_desktopimgdownldr.yml
  * T1197 [Bits download using desktopimgdownldr.exe (cmd)](tests/afb5e09e-e385-4dee-9a94-6ee60979d114.md)
* proc_creation_win_susp_dir.yml
  * T1217 [List Internet Explorer Bookmarks using the command prompt](tests/727dbcdb-e495-4ab1-a6c4-80c7f77aef85.md)
  * T1552.004 [Private Keys](tests/520ce462-7ca7-441e-b5a5-f8347f632696.md)
* proc_creation_win_susp_direct_asep_reg_keys_modification.yml
  * T1547.001 [Reg Key Run](tests/e55be3fd-3521-4610-9d1a-e210e42dcf05.md)
  * T1112 [Modify Registry of Local Machine - cmd](tests/282f929a-6bc5-42b8-bd93-960c3ba35afe.md)
  * T1547.001 [Reg Key RunOnce](tests/554cbd88-cde1-4b56-8168-0be552eed9eb.md)
* proc_creation_win_susp_diskshadow.yml
  * T1218 [DiskShadow Command Execution](tests/0e1483ba-8f0c-425d-b8c6-42736e058eaa.md)
* proc_creation_win_susp_double_extension.yml
  * T1036.003 [File Extension Masquerading](tests/c7fa0c3b-b57f-4cba-9118-863bf4e653fc.md)
* proc_creation_win_susp_eventlog_clear.yml
  * T1070.001 [Clear Logs](tests/e6abb60e-26b8-41da-8aae-0c35174b0967.md)
  * T1070.001 [Delete System Logs Using Clear-EventLog](tests/b13e9306-3351-4b4b-a6e8-477358b0b498.md)
  * T1562.002 [Disable Event Logging with wevtutil](tests/b26a3340-dad7-4360-9176-706269c74103.md)
* proc_creation_win_susp_execution_path.yml
  * T1218.004 [InstallUtil evasive invocation](tests/559e6d06-bb42-4307-bff7-3b95a8254bad.md)
* proc_creation_win_susp_findstr.yml
  * T1564.004 [Alternate Data Streams (ADS)](tests/8822c3b0-d9f9-4daf-a043-49f4602364f4.md)
* proc_creation_win_susp_findstr_385201.yml
  * T1518.001 [Security Software Discovery - Sysmon Service](tests/fe613cf3-8009-4446-9a0f-bc78a15b66c9.md)
* proc_creation_win_susp_finger_usage.yml
  * T1105 [File download with finger.exe on Windows](tests/5f507e45-8411-4f99-84e7-e38530c45d01.md)
* proc_creation_win_susp_firewall_disable.yml
  * T1562.004 [Disable Microsoft Defender Firewall](tests/88d05800-a5e4-407e-9b53-ece4174f197f.md)
* proc_creation_win_susp_fsutil_usage.yml
  * T1070 [Indicator Removal using FSUtil](tests/b4115c7a-0e92-47f0-a61e-17e7218b2435.md)
* proc_creation_win_susp_gup.yml
  * T1574.002 [DLL Side-Loading using the Notepad++ GUP.exe binary](tests/65526037-7079-44a9-bda1-2cb624838040.md)
* proc_creation_win_susp_hostname.yml
  * T1036.003 [File Extension Masquerading](tests/c7fa0c3b-b57f-4cba-9118-863bf4e653fc.md)
  * T1082 [Hostname Discovery (Windows)](tests/85cfbf23-4a1e-4342-8792-007e004b975f.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
* proc_creation_win_susp_machineguid.yml
  * T1082 [Windows MachineGUID Discovery](tests/224b4daf-db44-404e-b6b2-f4d1f0126ef8.md)
* proc_creation_win_susp_mounted_share_deletion.yml
  * T1070.005 [Remove Administrative Shares](tests/4299eff5-90f1-4446-b2f3-7f4f5cfd5d62.md)
  * T1070.005 [Remove Network Share](tests/09210ad5-1ef2-4077-9ad3-7351e13e9222.md)
* proc_creation_win_susp_mpcmdrun_download.yml
  * T1105 [Download a File with Windows Defender MpCmdRun.exe](tests/815bef8b-bf91-4b67-be4c-abe4c2a94ccc.md)
* proc_creation_win_susp_mshta_execution.yml
  * T1218.005 [Mshta used to Execute PowerShell](tests/8707a805-2b76-4f32-b1c0-14e558205772.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement](tests/007e5672-2088-4853-a562-7490ddc19447.md)
  * T1218.005 [Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md)
  * T1204.002 [Headless Chrome code execution via VBA](tests/a19ee671-ed98-4e9d-b19c-d1954a51585a.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1218.005 [Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject](tests/1483fab9-4f52-4217-a9ce-daa9d7747cae.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
  * T1218.005 [Mshta Executes Remote HTML Application (HTA)](tests/c4b97eeb-5249-4455-a607-59f95485cb45.md)
  * T1218.005 [Mshta executes VBScript to execute malicious command](tests/906865c3-e05f-4acc-85c4-fbc185455095.md)
  * T1059.001 [Powershell invoke mshta.exe download](tests/8a2ad40b-12c7-4b25-8521-2737b0a415af.md)
  * T1059.005 [Encoded VBS code execution](tests/e8209d5f-e42d-45e6-9c2f-633ac4f1eefa.md)
* proc_creation_win_susp_mshta_pattern.yml
  * T1218.005 [Mshta used to Execute PowerShell](tests/8707a805-2b76-4f32-b1c0-14e558205772.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement](tests/007e5672-2088-4853-a562-7490ddc19447.md)
  * T1218.005 [Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md)
  * T1204.002 [Headless Chrome code execution via VBA](tests/a19ee671-ed98-4e9d-b19c-d1954a51585a.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1218.005 [Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject](tests/1483fab9-4f52-4217-a9ce-daa9d7747cae.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
  * T1218.005 [Mshta Executes Remote HTML Application (HTA)](tests/c4b97eeb-5249-4455-a607-59f95485cb45.md)
  * T1218.005 [Mshta executes VBScript to execute malicious command](tests/906865c3-e05f-4acc-85c4-fbc185455095.md)
  * T1059.001 [Powershell invoke mshta.exe download](tests/8a2ad40b-12c7-4b25-8521-2737b0a415af.md)
  * T1059.005 [Encoded VBS code execution](tests/e8209d5f-e42d-45e6-9c2f-633ac4f1eefa.md)
* proc_creation_win_susp_msoffice.yml
  * T1218 [ProtocolHandler.exe Downloaded a Suspicious File](tests/db020456-125b-4c8b-a4a7-487df8afb5a2.md)
* proc_creation_win_susp_net_execution.yml
  * T1201 [Examine local password policy - Windows](tests/4588d243-f24e-4549-b2e3-e627acc089f6.md)
  * T1070.005 [Remove Administrative Shares](tests/4299eff5-90f1-4446-b2f3-7f4f5cfd5d62.md)
  * T1087.001 [Enumerate all accounts via PowerShell (Local)](tests/ae4b6361-b5f8-46cb-a3f9-9cf108ccfe7b.md)
  * T1136.002 [Create a new account similar to ANONYMOUS LOGON](tests/dc7726d2-8ccb-4cc6-af22-0d5afb53a548.md)
  * T1136.002 [Create a new Windows domain admin user](tests/fcec2963-9951-4173-9bfa-98d8b7834e62.md)
  * T1016 [System Network Configuration Discovery (TrickBot Style)](tests/dafaf052-5508-402d-bf77-51e0700c02e2.md)
  * T1016 [Qakbot Recon](tests/121de5c6-5818-4868-b8a7-8fd07c455c1b.md)
  * T1135 [View available share drives](tests/ab39a04f-0c93-4540-9ff2-83f862c385ae.md)
  * T1087.001 [Enumerate all accounts on Windows (Local)](tests/80887bec-5a9b-4efc-a81d-f83eb2eb32ab.md)
  * T1136.001 [Create a new user in a command prompt](tests/6657864e-0323-4206-9344-ac9cd7265a4f.md)
  * T1078.001 [Activate Guest Account](tests/aa6cb8c4-b582-4f8e-b677-37733914abda.md)
  * T1531 [Delete User - Windows](tests/f21a1d7d-a62f-442a-8c3a-2440d43b19e5.md)
  * T1135 [Network Share Discovery command prompt](tests/20f1097d-81c1-405c-8380-32174d493bbb.md)
  * T1078.003 [Create local account with admin privileges](tests/a524ce99-86de-4db6-b4f9-e08f35a47a15.md)
  * T1007 [System Service Discovery - net.exe](tests/5f864a3f-8ce9-45c0-812c-bdf7d8aeacc3.md)
  * T1563.002 [RDP hijacking](tests/a37ac520-b911-458e-8aed-c5f1576d9f46.md)
  * T1110.003 [Password Spray (DomainPasswordSpray)](tests/263ae743-515f-4786-ac7d-41ef3a0d4b2b.md)
  * T1078.001 [Enable Guest account with RDP capability and admin privileges](tests/99747561-ed8d-47f2-9c91-1e5fde1ed6e0.md)
  * T1562.001 [Disable Arbitrary Security Windows Service](tests/a1230893-56ac-4c81-b644-2108e982f8f5.md)
  * T1069.002 [Elevated group enumeration using net group (Domain)](tests/0afb5163-8181-432e-9405-4322710c0c37.md)
  * T1564 [Create a Hidden User Called "$"](tests/2ec63cc2-4975-41a6-bf09-dffdfb610778.md)
  * T1070.005 [Add Network Share](tests/14c38f32-6509-46d8-ab43-d53e32d2b131.md)
  * T1087.002 [Enumerate Default Domain Admin Details (Domain)](tests/c70ab9fd-19e2-4e02-a83c-9cfa8eaa8fef.md)
  * T1087.002 [Enumerate all accounts (Domain)](tests/6fbc9e68-5ad7-444a-bd11-8bf3136c477e.md)
  * T1136.001 [Create a new Windows admin user](tests/fda74566-a604-4581-a4cc-fbbe21d66559.md)
  * T1018 [Remote System Discovery - net](tests/85321a9c-897f-4a60-9f20-29788e50bccd.md)
  * T1531 [Change User Password - Windows](tests/1b99ef28-f83c-4ec5-8a08-1a56263a5bb2.md)
  * T1018 [Remote System Discovery - net group Domain Computers](tests/f1bf6c8f-9016-4edf-aff9-80b65f5d711f.md)
  * T1201 [Examine domain password policy - Windows](tests/46c2c362-2679-4ef5-aec9-0e958e135be4.md)
  * T1489 [Windows - Stop service using net.exe](tests/41274289-ec9c-4213-bea4-e43c4aa57954.md)
  * T1069.001 [Basic Permission Groups Discovery Windows (Local)](tests/1f454dd6-e134-44df-bebb-67de70fb6cd8.md)
  * T1069.002 [Basic Permission Groups Discovery Windows (Domain)](tests/dd66d77d-8998-48c0-8024-df263dc2ce5d.md)
  * T1070.005 [Remove Network Share](tests/09210ad5-1ef2-4077-9ad3-7351e13e9222.md)
* proc_creation_win_susp_netsh_command.yml
  * T1016 [List Windows Firewall Rules](tests/038263cb-00f4-4b0a-98ae-0696c67e1752.md)
* proc_creation_win_susp_netsh_dll_persistence.yml
  * T1546.007 [Netsh Helper DLL Registration](tests/3244697d-5a3a-4dfc-941c-550f69f91a4d.md)
* proc_creation_win_susp_network_command.yml
  * T1018 [Remote System Discovery - arp](tests/2d5a61f5-0447-4be4-944a-1f8530ed6574.md)
  * T1016 [System Network Configuration Discovery (TrickBot Style)](tests/dafaf052-5508-402d-bf77-51e0700c02e2.md)
  * T1016 [System Network Configuration Discovery on Windows](tests/970ab6a1-0157-4f3f-9a73-ec4166754b23.md)
* proc_creation_win_susp_network_listing_connections.yml
  * T1016 [Qakbot Recon](tests/121de5c6-5818-4868-b8a7-8fd07c455c1b.md)
  * T1110.001 [Brute Force Credentials of single Active Directory domain users via SMB](tests/09480053-2f98-4854-be6e-71ae5f672224.md)
  * T1049 [System Network Connections Discovery](tests/0940a971-809a-48f1-9c4d-b1d785e96ee5.md)
  * T1070.005 [Add Network Share](tests/14c38f32-6509-46d8-ab43-d53e32d2b131.md)
  * T1021.002 [Map admin share](tests/3386975b-367a-4fbb-9d77-4dcf3639ffd3.md)
* proc_creation_win_susp_nmap.yml
  * T1046 [Port Scan Nmap](tests/515942b0-a09f-4163-a7bb-22fefb6f185f.md)
  * T1046 [Port Scan NMap for Windows](tests/d696a3cb-d7a8-4976-8eb5-5af4abf2e3df.md)
* proc_creation_win_susp_non_exe_image.yml
  * T1140 [Certutil Rename and Decode](tests/71abc534-3c05-4d0c-80f7-cbe93cb2aa94.md)
* proc_creation_win_susp_ntdsutil.yml
  * T1003.003 [Dump Active Directory Database with NTDSUtil](tests/2364e33d-ceab-4641-8468-bfb1d7cc2723.md)
  * T1098 [Password Change on Directory Service Restore Mode (DSRM) Account](tests/d5b886d9-d1c7-4b6e-a7b0-460041bf2823.md)
* proc_creation_win_susp_odbcconf.yml
  * T1218.008 [Odbcconf.exe - Execute Arbitrary DLL](tests/2430498b-06c0-4b92-a448-8ad263c388e2.md)
* proc_creation_win_susp_pcwutl.yml
  * T1218.011 [Launches an executable using Rundll32 and pcwutl.dll](tests/9f5d081a-ee5a-42f9-a04e-b7bdc487e676.md)
* proc_creation_win_susp_powershell_download_cradles.yml
  * T1615 [Get-DomainGPO to display group policy information via PowerView](tests/4e524c4e-0e02-49aa-8df5-93f3f7959b9f.md)
* proc_creation_win_susp_powershell_download_iex.yml
  * T1615 [Get-DomainGPO to display group policy information via PowerView](tests/4e524c4e-0e02-49aa-8df5-93f3f7959b9f.md)
* proc_creation_win_susp_powershell_encode.yml
  * T1218.001 [Invoke CHM Shortcut Command with ITS and Help Topic](tests/15756147-7470-4a83-87fb-bb5662526247.md)
  * T1218.001 [Invoke CHM with default Shortcut Command Execution](tests/29d6f0d7-be63-4482-8827-ea77126c1ef7.md)
  * T1218.001 [Invoke CHM with Script Engine and Help Topic](tests/4f83adda-f5ec-406d-b318-9773c9ca92e5.md)
  * T1218.001 [Invoke CHM with InfoTech Storage Protocol Handler](tests/b4094750-5fc7-4e8e-af12-b4e36bf5e7f6.md)
  * T1027 [Execute base64-encoded PowerShell](tests/a50d5a97-2531-499e-a1de-5544c74432c6.md)
  * T1059.001 [PowerShell Command Execution](tests/a538de64-1c74-46ed-aa60-b995ed302598.md)
  * T1059.001 [Obfuscation Tests](tests/4297c41a-8168-4138-972d-01f3ee92c804.md)
  * T1218.009 [Regsvcs Uninstall Method Call Test](tests/fd3c1c6a-02d2-4b72-82d9-71c527abb126.md)
  * T1218.001 [Invoke CHM Simulate Double click](tests/5decef42-92b8-4a93-9eb2-877ddcb9401a.md)
* proc_creation_win_susp_powershell_getprocess_lsass.yml
  * T1003.001 [Dump LSASS.exe Memory using comsvcs.dll](tests/2536dee2-12fb-459a-8c37-971844fa73be.md)
  * T1003.001 [Dump LSASS.exe Memory using Out-Minidump.ps1](tests/6502c8f0-b775-4dbd-9193-1298f56b6781.md)
* proc_creation_win_susp_powershell_parent_combo.yml
  * T1216 [SyncAppvPublishingServer Signed Script PowerShell Command Execution](tests/275d963d-3f36-476c-8bef-a2a3960ee6eb.md)
* proc_creation_win_susp_powershell_parent_process.yml
  * T1218.005 [Mshta used to Execute PowerShell](tests/8707a805-2b76-4f32-b1c0-14e558205772.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Rundll32 and Inline Protocol Handler](tests/e7e3a525-7612-4d68-a5d3-c4649181b8af.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement](tests/007e5672-2088-4853-a562-7490ddc19447.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations](tests/686a9785-f99b-41d4-90df-66ed515f81d7.md)
  * T1204.002 [Office Generic Payload Download](tests/5202ee05-c420-4148-bf5e-fd7f7d24850c.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations](tests/86a43bad-12e3-4e85-b97c-4d5cf25b95c3.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments](tests/0d181431-ddf3-4826-8055-2dbf63ae848b.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
  * T1559.002 [Execute PowerShell script via Word DDE](tests/47c21fb6-085e-4b0d-b4d2-26d72c3830b3.md)
  * T1569.002 [Execute a Command as a Service](tests/2382dee2-a75f-49aa-9378-f52df6ed3fb1.md)
  * T1218.005 [Mshta executes VBScript to execute malicious command](tests/906865c3-e05f-4acc-85c4-fbc185455095.md)
  * T1059.001 [Powershell invoke mshta.exe download](tests/8a2ad40b-12c7-4b25-8521-2737b0a415af.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments](tests/1c0a870f-dc74-49cf-9afc-eccc45e58790.md)
* proc_creation_win_susp_powershell_sam_access.yml
  * T1003.002 [dump volume shadow copy hives with System.IO.File](tests/9d77fed7-05f8-476e-a81b-8ff0472c64d0.md)
* proc_creation_win_susp_print.yml
  * T1564.004 [Alternate Data Streams (ADS)](tests/8822c3b0-d9f9-4daf-a043-49f4602364f4.md)
* proc_creation_win_susp_procdump.yml
  * T1003.001 [Dump LSASS.exe Memory using ProcDump](tests/0be2230c-9ab3-4ac2-8826-3199b9a0ebf8.md)
* proc_creation_win_susp_procdump_lsass.yml
  * T1003.001 [Dump LSASS.exe Memory using ProcDump](tests/0be2230c-9ab3-4ac2-8826-3199b9a0ebf8.md)
* proc_creation_win_susp_progname.yml
  * T1572 [DNS over HTTPS Regular Beaconing](tests/0c5f9705-c575-42a6-9609-cbbff4b2fc9b.md)
  * T1201 [Get-DomainPolicy with PowerView](tests/3177f4da-3d4b-4592-8bdc-aa23d0b2e843.md)
  * T1069.002 [Get-DomainGroupMember with PowerView](tests/46352f40-f283-4fe5-b56d-d9a71750e145.md)
  * T1615 [Get-DomainGPO to display group policy information via PowerView](tests/4e524c4e-0e02-49aa-8df5-93f3f7959b9f.md)
  * T1018 [Get-DomainController with PowerView](tests/b9d2e8ca-5520-4737-8076-4f08913da2c4.md)
  * T1087.002 [Get-DomainUser with PowerView](tests/93662494-5ed7-4454-a04c-8c8372808ac2.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
  * T1069.002 [Get-DomainGroup with PowerView](tests/5a8a181c-2c8e-478d-a943-549305a01230.md)
* proc_creation_win_susp_ps_downloadfile.yml
  * T1105 [Windows - PowerShell Download](tests/42dc4460-9aa6-45d3-b1a6-3955d34e1fe8.md)
* proc_creation_win_susp_psexec_eula.yml
  * T1207 [DCShadow (Active Directory)](tests/0f4c5eb0-98a0-4496-9c3d-656b4f2bc8f6.md)
  * T1550.003 [Rubeus Kerberos Pass The Ticket](tests/a2fc4ec5-12c6-4fb4-b661-961f23f359cb.md)
  * T1562.006 [Disable Powershell ETW Provider - Windows](tests/6f118276-121d-4c09-bb58-a8fb4a72ee84.md)
  * T1003.004 [Dumping LSA Secrets](tests/55295ab0-a703-433b-9ca4-ae13807de12f.md)
  * T1021.002 [Copy and Execute File with PsExec](tests/0eb03d41-79e4-4393-8e57-6344856be1cf.md)
  * T1569.002 [Use PsExec to execute a command on a remote host](tests/873106b7-cfed-454b-8680-fa9f6400431c.md)
  * T1055 [Remote Process Injection in LSASS via mimikatz](tests/3203ad24-168e-4bec-be36-f79b13ef8a83.md)
* proc_creation_win_susp_psloglist.yml
  * T1003.004 [Dumping LSA Secrets](tests/55295ab0-a703-433b-9ca4-ae13807de12f.md)
* proc_creation_win_susp_psr_capture_screenshots.yml
  * T1113 [Windows Screencapture](tests/3c898f62-626c-47d5-aad2-6de873d69153.md)
* proc_creation_win_susp_radmin.yml
  * T1072 [Radmin Viewer Utility](tests/b4988cad-6ed2-434d-ace5-ea2670782129.md)
* proc_creation_win_susp_recon.yml
  * T1119 [Recon information for export with Command Prompt](tests/aa1180e2-f329-4e1e-8625-2472ec0bfaf3.md)
* proc_creation_win_susp_reg_open_command.yml
  * T1548.002 [Bypass UAC using Fodhelper](tests/58f641ea-12e3-499a-b684-44dee46bd182.md)
* proc_creation_win_susp_register_cimprovider.yml
  * T1218 [Register-CimProvider - Execute evil dll](tests/ad2c17ed-f626-4061-b21e-b9804a6f3655.md)
* proc_creation_win_susp_regsvr32_anomalies.yml
  * T1218.010 [Regsvr32 Silent DLL Install Call DllRegisterServer](tests/9d71c492-ea2e-4c08-af16-c6994cdf029f.md)
  * T1218.010 [Regsvr32 Registering Non DLL](tests/1ae5ea1f-0a4e-4e54-b2f5-4ac328a7f421.md)
  * T1564.006 [Register Portable Virtualbox](tests/c59f246a-34f8-4e4d-9276-c295ef9ba0dd.md)
  * T1218.010 [Regsvr32 local COM scriptlet execution](tests/449aa403-6aba-47ce-8a37-247d21ef0306.md)
  * T1218.010 [Regsvr32 local DLL execution](tests/08ffca73-9a3d-471a-aeb0-68b4aa3ab37b.md)
  * T1218.010 [Regsvr32 remote COM scriptlet execution](tests/c9d0c4ef-8a96-4794-a75b-3d3a5e6f2a36.md)
* proc_creation_win_susp_regsvr32_flags_anomaly.yml
  * T1218.010 [Regsvr32 local COM scriptlet execution](tests/449aa403-6aba-47ce-8a37-247d21ef0306.md)
  * T1218.010 [Regsvr32 remote COM scriptlet execution](tests/c9d0c4ef-8a96-4794-a75b-3d3a5e6f2a36.md)
* proc_creation_win_susp_regsvr32_no_dll.yml
  * T1218.010 [Regsvr32 Registering Non DLL](tests/1ae5ea1f-0a4e-4e54-b2f5-4ac328a7f421.md)
* proc_creation_win_susp_run_folder.yml
  * T1219 [GoToAssist Files Detected Test on Windows](tests/1b72b3bd-72f8-4b63-a30b-84e91b9c3578.md)
  * T1562.001 [Disable Defender with Defender Control](tests/178136d8-2778-4d7a-81f3-d517053a4fd6.md)
  * T1539 [Steal Firefox Cookies (Windows)](tests/4b437357-f4e9-4c84-9fa6-9bcee6f826aa.md)
  * T1036.005 [Masquerade as a built-in system executable](tests/35eb8d16-9820-4423-a2a1-90c4f5edd9ca.md)
  * T1219 [AnyDesk Files Detected Test on Windows](tests/6b8b7391-5c0a-4f8c-baee-78d8ce0ce330.md)
  * T1562.006 [Disable Powershell ETW Provider - Windows](tests/6f118276-121d-4c09-bb58-a8fb4a72ee84.md)
  * T1219 [Ammyy Admin Software Execution](tests/0ae9e327-3251-465a-a53b-485d4e3f58fa.md)
  * T1539 [Steal Chrome Cookies (Windows)](tests/26a6b840-4943-4965-8df5-ef1f9a282440.md)
  * T1090.003 [Tor Proxy Usage - Windows](tests/7b9d85e5-c4ce-4434-8060-d3de83595e69.md)
  * T1558.002 [Crafting Active Directory silver tickets with mimikatz](tests/385e59aa-113e-4711-84d9-f637aef01f2c.md)
  * T1218.011 [Rundll32 with desk.cpl](tests/83a95136-a496-423c-81d3-1c6750133917.md)
  * T1090.003 [Psiphon](tests/14d55ca0-920e-4b44-8425-37eedd72b173.md)
  * T1219 [RemotePC Software Execution](tests/fbff3f1f-b0bf-448e-840f-7e1687affdce.md)
  * T1090.003 [Tor Proxy Usage - Debian/Ubuntu](tests/5ff9d047-6e9c-4357-b39b-5cf89d9b59c7.md)
  * T1219 [ScreenConnect Application Download and Install on Windows](tests/4a18cc4e-416f-4966-9a9d-75731c4684c0.md)
  * T1562.001 [Disable Defender Using NirSoft AdvancedRun](tests/81ce22fd-9612-4154-918e-8a1f285d214d.md)
* proc_creation_win_susp_run_locations.yml
  * T1218.004 [InstallUtil evasive invocation](tests/559e6d06-bb42-4307-bff7-3b95a8254bad.md)
* proc_creation_win_susp_rundll32_activity.yml
  * T1218.011 [Rundll32 ieadvpack.dll Execution](tests/5e46a58e-cbf6-45ef-a289-ed7754603df9.md)
  * T1218.002 [Control Panel Items](tests/037e9d8a-9e46-4255-8b33-2ae3b545ca6f.md)
  * T1218.011 [Rundll32 with Control_RunDLL](tests/e4c04b6f-c492-4782-82c7-3bf75eb8077e.md)
  * T1218.011 [Rundll32 advpack.dll Execution](tests/d91cae26-7fc1-457b-a854-34c8aad48c89.md)
  * T1218.011 [Rundll32 syssetup.dll Execution](tests/41fa324a-3946-401e-bbdd-d7991c628125.md)
  * T1218.011 [Execution of HTA and VBS Files using Rundll32 and URL.dll](tests/22cfde89-befe-4e15-9753-47306b37a6e3.md)
  * T1218.011 [Launches an executable using Rundll32 and pcwutl.dll](tests/9f5d081a-ee5a-42f9-a04e-b7bdc487e676.md)
  * T1218.011 [Rundll32 setupapi.dll Execution](tests/71d771cd-d6b3-4f34-bc76-a63d47a10b19.md)
* proc_creation_win_susp_rundll32_by_ordinal.yml
  * T1218.002 [Control Panel Items](tests/037e9d8a-9e46-4255-8b33-2ae3b545ca6f.md)
  * T1218.011 [Rundll32 with Ordinal Value](tests/9fd5a74b-ba89-482a-8a3e-a5feaa3697b0.md)
* proc_creation_win_susp_rundll32_script_run.yml
  * T1218.011 [Rundll32 execute JavaScript Remote Payload With GetObject](tests/cf3bdb9a-dd11-4b6c-b0d0-9e22b68a71be.md)
  * T1218.011 [Rundll32 execute VBscript command](tests/638730e7-7aed-43dc-bf8c-8117f805f5bb.md)
* proc_creation_win_susp_sc_query.yml
  * T1119 [Recon information for export with Command Prompt](tests/aa1180e2-f329-4e1e-8625-2472ec0bfaf3.md)
  * T1007 [System Service Discovery](tests/89676ba1-b1f8-47ee-b940-2e1a113ebc71.md)
  * T1562.001 [Tamper with Windows Defender Command Prompt](tests/aa875ed4-8935-47e2-b2c5-6ec00ab220d2.md)
* proc_creation_win_susp_schtask_creation.yml
  * T1036.004 [Creating W32Time similar named service using schtasks](tests/f9f2fe59-96f7-4a7d-ba9f-a9783200d4c9.md)
  * T1053.005 [Scheduled task Local](tests/42f53695-ad4a-4546-abb6-7d837f644a71.md)
  * T1053.005 [Scheduled task Remote](tests/2e5eac3e-327b-4a88-a0c0-c4057039a8dd.md)
  * T1053.005 [Scheduled Task Startup Script](tests/fec27f65-db86-4c2d-b66c-61945aee87c2.md)
  * T1053.005 [Scheduled Task Executing Base64 Encoded Commands From Registry](tests/e895677d-4f06-49ab-91b6-ae3742d0a2ba.md)
  * T1219 [TeamViewer Files Detected Test on Windows](tests/8ca3b96d-8983-4a7f-b125-fc98cc0a2aa0.md)
* proc_creation_win_susp_schtasks_disable.yml
  * T1490 [Windows - Disable the SR scheduled task](tests/1c68c68d-83a4-4981-974e-8993055fa034.md)
* proc_creation_win_susp_schtasks_user_temp.yml
  * T1219 [TeamViewer Files Detected Test on Windows](tests/8ca3b96d-8983-4a7f-b125-fc98cc0a2aa0.md)
* proc_creation_win_susp_screensaver_reg.yml
  * T1546.002 [Set Arbitrary Binary as Screensaver](tests/281201e7-de41-4dc9-b73d-f288938cbb64.md)
* proc_creation_win_susp_script_exec_from_temp.yml
  * T1036.003 [File Extension Masquerading](tests/c7fa0c3b-b57f-4cba-9118-863bf4e653fc.md)
  * T1003.001 [Dump LSASS with .Net 5 createdump.exe](tests/9d0072c8-7cca-45c4-bd14-f852cfa35cf0.md)
  * T1137.006 [Code Executed Via Excel Add-in File (Xll)](tests/441b1a0f-a771-428a-8af0-e99e4698cda3.md)
  * T1204.002 [Excel 4 Macro](tests/4ea1fc97-8a46-4b4e-ba48-af43d2a98052.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1039 [Copy a sensitive File over Administive share with Powershell](tests/7762e120-5879-44ff-97f8-008b401b9a98.md)
  * T1114.001 [Email Collection with PowerShell Get-Inbox](tests/3f1b5096-0139-4736-9b78-19bcb02bb1cb.md)
  * T1204.002 [OSTap Payload Download](tests/3f3af983-118a-4fa1-85d3-ba4daa739d80.md)
* proc_creation_win_susp_script_execution.yml
  * T1204.002 [OSTAP JS version](tests/add560ef-20d6-4011-a937-2c340f930911.md)
  * T1547.001 [Suspicious jse file run from startup Folder](tests/dade9447-791e-4c8f-b04b-3a35855dfa06.md)
  * T1204.002 [OSTap Style Macro Execution](tests/8bebc690-18c7-4549-bc98-210f7019efff.md)
  * T1105 [OSTAP Worming Activity](tests/2ca61766-b456-4fcf-a35a-1233685e1cad.md)
  * T1204.002 [OSTap Payload Download](tests/3f3af983-118a-4fa1-85d3-ba4daa739d80.md)
* proc_creation_win_susp_service_modification.yml
  * T1562.001 [Stop and Remove Arbitrary Security Windows Service](tests/ae753dda-0f15-4af6-a168-b9ba16143143.md)
* proc_creation_win_susp_service_path_modification.yml
  * T1543.003 [Modify Fax service to run PowerShell](tests/ed366cde-7d12-49df-a833-671904770b9f.md)
* proc_creation_win_susp_sharpview.yml
  * T1049 [System Discovery using SharpView](tests/96f974bb-a0da-4d87-a744-ff33e73367e9.md)
* proc_creation_win_susp_shutdown.yml
  * T1529 [Shutdown System - Windows](tests/ad254fa8-45c0-403b-8c77-e00b3d3e7a64.md)
  * T1529 [Restart System - Windows](tests/f4648f0d-bf78-483c-bafc-3ec99cd1c302.md)
* proc_creation_win_susp_svchost.yml
  * T1036.003 [Masquerading - windows exe running as different windows exe](tests/c3d24a39-2bfe-4c6a-b064-90cd73896cb0.md)
  * T1036.005 [Masquerade as a built-in system executable](tests/35eb8d16-9820-4423-a2a1-90c4f5edd9ca.md)
  * T1036.003 [Masquerading - wscript.exe running as svchost.exe](tests/24136435-c91a-4ede-9da1-8b284a1c1a23.md)
  * T1036.003 [Masquerading - non-windows exe running as windows exe](tests/bc15c13f-d121-4b1f-8c7d-28d95854d086.md)
  * T1105 [svchost writing a file to a UNC path](tests/fa5a2759-41d7-4e13-a19c-e8f28a53566f.md)
  * T1218 [Renamed Microsoft.Workflow.Compiler.exe Payload Executions](tests/4cc40fd7-87b8-4b16-b2d7-57534b86b911.md)
* proc_creation_win_susp_systeminfo.yml
  * T1082 [System Information Discovery](tests/66703791-c902-4560-8770-42b8a91f7667.md)
* proc_creation_win_susp_takeown.yml
  * T1222.001 [Take ownership using takeown utility](tests/98d34bb4-6e75-42ad-9c41-1dae7dc6a001.md)
* proc_creation_win_susp_taskkill.yml
  * T1105 [Download a file with Microsoft Connection Manager Auto-Download](tests/d239772b-88e2-4a2e-8473-897503401bcc.md)
  * T1090.003 [Psiphon](tests/14d55ca0-920e-4b44-8425-37eedd72b173.md)
  * T1219 [RemotePC Software Execution](tests/fbff3f1f-b0bf-448e-840f-7e1687affdce.md)
* proc_creation_win_susp_tasklist_command.yml
  * T1003.001 [Dump LSASS with .Net 5 createdump.exe](tests/9d0072c8-7cca-45c4-bd14-f852cfa35cf0.md)
  * T1518.001 [Security Software Discovery](tests/f92a380f-ced9-491f-b338-95a991418ce2.md)
  * T1057 [Process Discovery - tasklist](tests/c5806a4f-62b8-4900-980b-c7ec004e9908.md)
  * T1007 [System Service Discovery](tests/89676ba1-b1f8-47ee-b940-2e1a113ebc71.md)
* proc_creation_win_susp_tscon_localsystem.yml
  * T1563.002 [RDP hijacking](tests/a37ac520-b911-458e-8aed-c5f1576d9f46.md)
* proc_creation_win_susp_vaultcmd.yml
  * T1555.004 [Access Saved Credentials via VaultCmd](tests/9c2dd36d-5c8b-4b29-8d72-a11b0d5d7439.md)
* proc_creation_win_susp_web_request_cmd.yml
  * T1219 [GoToAssist Files Detected Test on Windows](tests/1b72b3bd-72f8-4b63-a30b-84e91b9c3578.md)
  * T1105 [Windows - PowerShell Download](tests/42dc4460-9aa6-45d3-b1a6-3955d34e1fe8.md)
  * T1095 [Powercat C2](tests/3e0e0e7f-6aa2-4a61-b61d-526c2cc9330e.md)
  * T1059.001 [Run Bloodhound from Memory using Download Cradle](tests/bf8c1441-4674-4dab-8e4e-39d93d08f9b7.md)
  * T1095 [ICMP C2](tests/0268e63c-e244-42db-bef7-72a9e59fc1fc.md)
  * T1201 [Get-DomainPolicy with PowerView](tests/3177f4da-3d4b-4592-8bdc-aa23d0b2e843.md)
  * T1197 [Bitsadmin Download (PowerShell)](tests/f63b8bc4-07e5-4112-acba-56f646f3f0bc.md)
  * T1204.002 [Office Generic Payload Download](tests/5202ee05-c420-4148-bf5e-fd7f7d24850c.md)
  * T1071.004 [DNS C2](tests/e7bf9802-2e78-4db9-93b5-181b7bcd37d7.md)
  * T1027 [DLP Evasion via Sensitive Data in VBA Macro over HTTP](tests/e2d85e66-cb66-4ed7-93b1-833fc56c9319.md)
  * T1566.001 [Download Macro-Enabled Phishing Attachment](tests/114ccff9-ae6d-4547-9ead-4cd69f687306.md)
  * T1059.001 [Invoke-AppPathBypass](tests/06a220b6-7e29-4bd8-9d07-5b4d86742372.md)
  * T1105 [File Download via PowerShell](tests/54a4daf1-71df-4383-9ba7-f1a295d8b6d2.md)
  * T1557.001 [LLMNR Poisoning with Inveigh (PowerShell)](tests/deecd55f-afe0-4a62-9fba-4d1ba2deb321.md)
  * T1219 [LogMeIn Files Detected Test on Windows](tests/d03683ec-aae0-42f9-9b4c-534780e0f8e1.md)
  * T1071.001 [Malicious User Agents - Powershell](tests/81c13829-f6c9-45b8-85a6-053366d55297.md)
  * T1204.002 [Potentially Unwanted Applications (PUA)](tests/02f35d62-9fdc-4a97-b899-a5d9a876d295.md)
  * T1069.002 [Get-DomainGroupMember with PowerView](tests/46352f40-f283-4fe5-b56d-d9a71750e145.md)
  * T1615 [Get-DomainGPO to display group policy information via PowerView](tests/4e524c4e-0e02-49aa-8df5-93f3f7959b9f.md)
  * T1553.004 [Add Root Certificate to CurrentUser Certificate Store](tests/ca20a3f1-42b5-4e21-ad3f-1049199ec2e0.md)
  * T1132.001 [XOR Encoded data.](tests/c3ed6d2a-e3ad-400d-ad78-bbfdbfeacc08.md)
  * T1056.004 [Hook PowerShell TLS Encrypt/Decrypt Messages](tests/de1934ea-1fbf-425b-8795-65fb27dd7e33.md)
  * T1559.002 [Execute PowerShell script via Word DDE](tests/47c21fb6-085e-4b0d-b4d2-26d72c3830b3.md)
  * T1219 [ScreenConnect Application Download and Install on Windows](tests/4a18cc4e-416f-4966-9a9d-75731c4684c0.md)
  * T1218.005 [Mshta Executes Remote HTML Application (HTA)](tests/c4b97eeb-5249-4455-a607-59f95485cb45.md)
  * T1550.002 [Invoke-WMIExec Pass the Hash](tests/f8757545-b00a-4e4e-8cfb-8cfb961ee713.md)
  * T1018 [Get-DomainController with PowerView](tests/b9d2e8ca-5520-4737-8076-4f08913da2c4.md)
  * T1087.002 [Get-DomainUser with PowerView](tests/93662494-5ed7-4454-a04c-8c8372808ac2.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
  * T1059.001 [Obfuscation Tests](tests/4297c41a-8168-4138-972d-01f3ee92c804.md)
  * T1069.002 [Get-DomainGroup with PowerView](tests/5a8a181c-2c8e-478d-a943-549305a01230.md)
  * T1219 [TeamViewer Files Detected Test on Windows](tests/8ca3b96d-8983-4a7f-b125-fc98cc0a2aa0.md)
* proc_creation_win_susp_webdav_client_execution.yml
  * T1110.003 [Password Spray all Domain Users](tests/90bc2e54-6c84-47a5-9439-0a2a92b4b175.md)
* proc_creation_win_susp_where_execution.yml
  * T1217 [List Google Chrome / Edge Chromium Bookmarks on Windows with command prompt](tests/76f71e2f-480e-4bed-b61e-398fe17499d5.md)
  * T1217 [List Mozilla Firefox bookmarks on Windows with command prompt](tests/4312cdbc-79fc-4a9c-becc-53d49c734bc5.md)
* proc_creation_win_susp_whoami.yml
  * T1036.003 [File Extension Masquerading](tests/c7fa0c3b-b57f-4cba-9118-863bf4e653fc.md)
  * T1558.004 [Get-DomainUser with PowerView](tests/d6139549-7b72-4e48-9ea1-324fc9bdf88a.md)
* proc_creation_win_susp_winzip.yml
  * T1560.001 [Compress Data and lock with password for Exfiltration with winzip](tests/01df0353-d531-408d-a0c5-3161bf822134.md)
* proc_creation_win_susp_wmi_execution.yml
  * T1047 [WMI Execute Remote Process](tests/9c8ef159-c666-472f-9874-90c8d60d136b.md)
  * T1047 [WMI Execute rundll32](tests/00738d2a-4651-4d76-adf2-c43a41dfb243.md)
  * T1003.003 [Create Volume Shadow Copy remotely (WMI) with esentutl](tests/21c7bf80-3e8b-40fa-8f9d-f5b194ff2865.md)
  * T1047 [WMI Execute Local Process](tests/b3bdfc91-b33e-4c6d-a5c8-d64bee0276b3.md)
  * T1518.001 [Security Software Discovery - AV Discovery via WMI](tests/1553252f-14ea-4d3b-8a08-d7a4211aa945.md)
* proc_creation_win_susp_wuauclt.yml
  * T1218 [Load Arbitrary DLL via Wuauclt (Windows Update Client)](tests/49fbd548-49e9-4bb7-94a6-3769613912b8.md)
* proc_creation_win_susp_zip_compress.yml
  * T1074.001 [Zip a Folder with PowerShell for Staging in Temp](tests/a57fbe4b-3440-452a-88a7-943531ac872a.md)
* proc_creation_win_suspicious_ad_reco.yml
  * T1069.001 [Wmic Group Discovery](tests/7413be50-be8e-430f-ad4d-07bf197884b2.md)
* proc_creation_win_syncappvpublishingserver_execute_powershell.yml
  * T1218 [SyncAppvPublishingServer - Execute arbitrary PowerShell code](tests/d590097e-d402-44e2-ad72-2c6aa1ce78b1.md)
* proc_creation_win_syncappvpublishingserver_vbs_execute_powershell.yml
  * T1216 [SyncAppvPublishingServer Signed Script PowerShell Command Execution](tests/275d963d-3f36-476c-8bef-a2a3960ee6eb.md)
* proc_creation_win_sysinternals_eula_accepted.yml
  * T1003.001 [Dump LSASS.exe Memory using ProcDump](tests/0be2230c-9ab3-4ac2-8826-3199b9a0ebf8.md)
  * T1550.003 [Rubeus Kerberos Pass The Ticket](tests/a2fc4ec5-12c6-4fb4-b661-961f23f359cb.md)
  * T1562.006 [Disable Powershell ETW Provider - Windows](tests/6f118276-121d-4c09-bb58-a8fb4a72ee84.md)
  * T1003.004 [Dumping LSA Secrets](tests/55295ab0-a703-433b-9ca4-ae13807de12f.md)
  * T1003.001 [Create Mini Dump of LSASS.exe using ProcDump](tests/7cede33f-0acd-44ef-9774-15511300b24b.md)
  * T1021.002 [Copy and Execute File with PsExec](tests/0eb03d41-79e4-4393-8e57-6344856be1cf.md)
  * T1569.002 [Use PsExec to execute a command on a remote host](tests/873106b7-cfed-454b-8680-fa9f6400431c.md)
* proc_creation_win_sysmon_driver_unload.yml
  * T1562.001 [Unload Sysmon Filter Driver](tests/811b3e76-c41b-430c-ac0d-e2380bfaa164.md)
* proc_creation_win_system_exe_anomaly.yml
  * T1036.003 [Masquerading - windows exe running as different windows exe](tests/c3d24a39-2bfe-4c6a-b064-90cd73896cb0.md)
  * T1036.003 [Malicious process Masquerading as LSM.exe](tests/83810c46-f45e-4485-9ab6-8ed0e9e6ed7f.md)
  * T1036.005 [Masquerade as a built-in system executable](tests/35eb8d16-9820-4423-a2a1-90c4f5edd9ca.md)
  * T1036.003 [Masquerading as Windows LSASS process](tests/5ba5a3d1-cf3c-4499-968a-a93155d1f717.md)
  * T1036.003 [Masquerading - wscript.exe running as svchost.exe](tests/24136435-c91a-4ede-9da1-8b284a1c1a23.md)
  * T1036.003 [Masquerading - non-windows exe running as windows exe](tests/bc15c13f-d121-4b1f-8c7d-28d95854d086.md)
  * T1105 [svchost writing a file to a UNC path](tests/fa5a2759-41d7-4e13-a19c-e8f28a53566f.md)
  * T1218 [Renamed Microsoft.Workflow.Compiler.exe Payload Executions](tests/4cc40fd7-87b8-4b16-b2d7-57534b86b911.md)
* proc_creation_win_tools_relay_attacks.yml
  * T1187 [PetitPotam](tests/485ce873-2e65-4706-9c7e-ae3ab9e14213.md)
* proc_creation_win_tor_browser.yml
  * T1090.003 [Tor Proxy Usage - Windows](tests/7b9d85e5-c4ce-4434-8060-d3de83595e69.md)
  * T1090.003 [Tor Proxy Usage - Debian/Ubuntu](tests/5ff9d047-6e9c-4357-b39b-5cf89d9b59c7.md)
* proc_creation_win_trust_discovery.yml
  * T1482 [Windows - Discover domain trusts with dsquery](tests/4700a710-c821-4e17-a3ec-9e4c81d6845f.md)
  * T1482 [Windows - Discover domain trusts with nltest](tests/2e22641d-0498-48d2-b9ff-c71e496ccdbe.md)
  * T1016 [System Network Configuration Discovery (TrickBot Style)](tests/dafaf052-5508-402d-bf77-51e0700c02e2.md)
  * T1018 [Remote System Discovery - nltest](tests/52ab5108-3f6f-42fb-8ba3-73bc054f22c8.md)
* proc_creation_win_uac_cmstp.yml
  * T1218.003 [CMSTP Executing UAC Bypass](tests/748cb4f6-2fb3-4e97-b7ad-b22635a09ab0.md)
  * T1218.003 [CMSTP Executing Remote Scriptlet](tests/34e63321-9683-496b-bbc1-7566bc55e624.md)
* proc_creation_win_uac_fodhelper.yml
  * T1548.002 [Bypass UAC using Fodhelper](tests/58f641ea-12e3-499a-b684-44dee46bd182.md)
  * T1548.002 [Bypass UAC using Fodhelper - PowerShell](tests/3f627297-6c38-4e7d-a278-fc2563eaaeaa.md)
* proc_creation_win_uninstall_crowdstrike_falcon.yml
  * T1562.001 [Uninstall Crowdstrike Falcon on Windows](tests/b32b1ccf-f7c1-49bc-9ddd-7d7466a7b297.md)
* proc_creation_win_uninstall_sysmon.yml
  * T1562.001 [Uninstall Sysmon](tests/a316fb2e-5344-470d-91c1-23e15c374edc.md)
* proc_creation_win_visual_basic_compiler.yml
  * T1127.001 [MSBuild Bypass Using Inline Tasks (VB)](tests/ab042179-c0c5-402f-9bc8-42741f5ce359.md)
* proc_creation_win_win_exchange_transportagent.yml
  * T1505.002 [Install MS Exchange Transport Agent Persistence](tests/43e92449-ff60-46e9-83a3-1a38089df94d.md)
* proc_creation_win_wmi_spwns_powershell.yml
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations](tests/686a9785-f99b-41d4-90df-66ed515f81d7.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations](tests/86a43bad-12e3-4e85-b97c-4d5cf25b95c3.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments](tests/0d181431-ddf3-4826-8055-2dbf63ae848b.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments](tests/1c0a870f-dc74-49cf-9afc-eccc45e58790.md)
* proc_creation_win_wmic_reconnaissance.yml
  * T1047 [WMI Reconnaissance Processes](tests/5750aa16-0e59-4410-8b9a-8a47ca2788e2.md)
  * T1047 [WMI Reconnaissance Software](tests/718aebaa-d0e0-471a-8241-c5afa69c7414.md)
  * T1220 [WMIC bypass using remote XSL file](tests/7f5be499-33be-4129-a560-66021f379b9b.md)
  * T1220 [WMIC bypass using local XSL file](tests/1b237334-3e21-4a0c-8178-b8c996124988.md)
  * T1057 [Process Discovery - wmic process](tests/640cbf6d-659b-498b-ba53-f6dd1a1cc02c.md)
* proc_creation_win_wmic_remote_service.yml
  * T1047 [WMI Reconnaissance List Remote Services](tests/0fd48ef7-d890-4e93-a533-f7dedd5191d3.md)
* proc_creation_win_wmic_remove_application.yml
  * T1047 [Application uninstall using WMIC](tests/c510d25b-1667-467d-8331-a56d3e9bc4ff.md)
* proc_creation_win_wmiprvse_spawning_process.yml
  * T1218.005 [Invoke HTML Application - JScript Engine with Rundll32 and Inline Protocol Handler](tests/e7e3a525-7612-4d68-a5d3-c4649181b8af.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations](tests/686a9785-f99b-41d4-90df-66ed515f81d7.md)
  * T1218.005 [Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md)
  * T1218.005 [Invoke HTML Application - Jscript Engine Simulating Double Click](tests/58a193ec-131b-404e-b1ca-b35cf0b18c33.md)
  * T1218.001 [Invoke CHM Shortcut Command with ITS and Help Topic](tests/15756147-7470-4a83-87fb-bb5662526247.md)
  * T1047 [Create a Process using obfuscated Win32_Process](tests/10447c83-fc38-462a-a936-5102363b1c43.md)
  * T1218.005 [Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md)
  * T1218.001 [Invoke CHM with default Shortcut Command Execution](tests/29d6f0d7-be63-4482-8827-ea77126c1ef7.md)
  * T1218.001 [Invoke CHM with Script Engine and Help Topic](tests/4f83adda-f5ec-406d-b318-9773c9ca92e5.md)
  * T1047 [Create a Process using WMI Query and an Encoded Command](tests/7db7a7f9-9531-4840-9b30-46220135441c.md)
  * T1218.001 [Invoke CHM with InfoTech Storage Protocol Handler](tests/b4094750-5fc7-4e8e-af12-b4e36bf5e7f6.md)
  * T1047 [WMI Execute rundll32](tests/00738d2a-4651-4d76-adf2-c43a41dfb243.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations](tests/86a43bad-12e3-4e85-b97c-4d5cf25b95c3.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments](tests/0d181431-ddf3-4826-8055-2dbf63ae848b.md)
  * T1003.003 [Create Volume Shadow Copy remotely (WMI) with esentutl](tests/21c7bf80-3e8b-40fa-8f9d-f5b194ff2865.md)
  * T1218.005 [Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md)
  * T1047 [WMI Execute Local Process](tests/b3bdfc91-b33e-4c6d-a5c8-d64bee0276b3.md)
  * T1059.001 [ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments](tests/1c0a870f-dc74-49cf-9afc-eccc45e58790.md)
  * T1218.001 [Invoke CHM Simulate Double click](tests/5decef42-92b8-4a93-9eb2-877ddcb9401a.md)
* proc_creation_win_workflow_compiler.yml
  * T1218 [Microsoft.Workflow.Compiler.exe Payload Execution](tests/7cbb0f26-a4c1-4f77-b180-a009aa05637e.md)
  * T1218 [Renamed Microsoft.Workflow.Compiler.exe Payload Executions](tests/4cc40fd7-87b8-4b16-b2d7-57534b86b911.md)
* proc_creation_win_xsl_script_processing.yml
  * T1220 [WMIC bypass using remote XSL file](tests/7f5be499-33be-4129-a560-66021f379b9b.md)
  * T1220 [MSXSL Bypass using remote files](tests/a7c3ab07-52fb-49c8-ab6d-e9c6d4a0a985.md)
  * T1220 [WMIC bypass using local XSL file](tests/1b237334-3e21-4a0c-8178-b8c996124988.md)
  * T1220 [MSXSL Bypass using local files](tests/ca23bfb2-023f-49c5-8802-e66997de462d.md)
* registry_add_logon_scripts_userinitmprlogonscript_reg.yml
  * T1037.001 [Logon Scripts](tests/d6042746-07d4-4c92-9ad8-e644c114a231.md)
* registry_add_sysinternals_eula_accepted.yml
  * T1207 [DCShadow (Active Directory)](tests/0f4c5eb0-98a0-4496-9c3d-656b4f2bc8f6.md)
  * T1003.001 [Dump LSASS.exe Memory using ProcDump](tests/0be2230c-9ab3-4ac2-8826-3199b9a0ebf8.md)
  * T1485 [Windows - Overwrite file with Sysinternals SDelete](tests/476419b5-aebf-4366-a131-ae3e8dae5fc2.md)
  * T1550.003 [Rubeus Kerberos Pass The Ticket](tests/a2fc4ec5-12c6-4fb4-b661-961f23f359cb.md)
  * T1204.002 [Excel 4 Macro](tests/4ea1fc97-8a46-4b4e-ba48-af43d2a98052.md)
  * T1003.004 [Dumping LSA Secrets](tests/55295ab0-a703-433b-9ca4-ae13807de12f.md)
  * T1003.001 [Create Mini Dump of LSASS.exe using ProcDump](tests/7cede33f-0acd-44ef-9774-15511300b24b.md)
  * T1021.002 [Copy and Execute File with PsExec](tests/0eb03d41-79e4-4393-8e57-6344856be1cf.md)
  * T1569.002 [Use PsExec to execute a command on a remote host](tests/873106b7-cfed-454b-8680-fa9f6400431c.md)
  * T1055 [Remote Process Injection in LSASS via mimikatz](tests/3203ad24-168e-4bec-be36-f79b13ef8a83.md)
* registry_add_sysinternals_sdelete_registry_keys.yml
  * T1485 [Windows - Overwrite file with Sysinternals SDelete](tests/476419b5-aebf-4366-a131-ae3e8dae5fc2.md)
* registry_delete_removal_amsi_registry_key.yml
  * T1562.001 [AMSI Bypass - Remove AMSI Provider Reg Key](tests/13f09b91-c953-438e-845b-b585e51cac9b.md)
* registry_event_persistence_recycle_bin.yml
  * T1547.001 [Add persistance via Recycle bin](tests/bda6a3d6-7aa7-4e89-908b-306772e9662f.md)
* registry_event_shell_open_keys_manipulation.yml
  * T1548.002 [Bypass UAC using ComputerDefaults (PowerShell)](tests/3c51abf2-44bf-42d8-9111-dc96ff66750f.md)
  * T1548.002 [Bypass UAC using Fodhelper](tests/58f641ea-12e3-499a-b684-44dee46bd182.md)
  * T1548.002 [Bypass UAC using Fodhelper - PowerShell](tests/3f627297-6c38-4e7d-a278-fc2563eaaeaa.md)
* registry_event_ssp_added_lsa_config.yml
  * T1547.005 [Modify SSP configuration in registry](tests/afdfd7e3-8a0b-409f-85f7-886fdf249c9e.md)
* registry_event_stickykey_like_backdoor.yml
  * T1546.008 [Attaches Command Prompt as a Debugger to a List of Target Processes](tests/3309f53e-b22b-4eb6-8fd2-a6cf58b355a9.md)
* registry_event_susp_mic_cam_access.yml
  * T1125 [Registry artefact when application use webcam](tests/6581e4a7-42e3-43c5-a0d2-5a0d62f9702a.md)
  * T1123 [Registry artefact when application use microphone](tests/7a21cce2-6ada-4f7c-afd9-e1e9c481e44a.md)
* registry_event_trust_record_modification.yml
  * T1218 [ProtocolHandler.exe Downloaded a Suspicious File](tests/db020456-125b-4c8b-a4a7-487df8afb5a2.md)
* registry_set_add_load_service_in_safe_mode.yml
  * T1112 [Windows Add Registry Value to Load Service in Safe Mode without Network](tests/1dd59fb3-1cb3-4828-805d-cf80b4c3bbb5.md)
  * T1219 [Ammyy Admin Software Execution](tests/0ae9e327-3251-465a-a53b-485d4e3f58fa.md)
  * T1112 [Windows Add Registry Value to Load Service in Safe Mode with Network](tests/c173c948-65e5-499c-afbe-433722ed5bd4.md)
* registry_set_add_port_monitor.yml
  * T1547.010 [Add Port Monitor persistence in Registry](tests/d34ef297-f178-4462-871e-9ce618d44e50.md)
* registry_set_asep_reg_keys_modification_currentcontrolset.yml
  * T1556.002 [Install and Register Password Filter DLL](tests/a7961770-beb5-4134-9674-83d7e1fa865c.md)
  * T1547.010 [Add Port Monitor persistence in Registry](tests/d34ef297-f178-4462-871e-9ce618d44e50.md)
  * T1547.002 [Authentication Package](tests/be2590e8-4ac3-47ac-b4b5-945820f2fbe9.md)
  * T1003 [Credential Dumping with NPPSpy](tests/9e2173c0-ba26-4cdf-b0ed-8c54b27e3ad6.md)
* registry_set_asep_reg_keys_modification_currentversion.yml
  * T1547.001 [Reg Key Run](tests/e55be3fd-3521-4610-9d1a-e210e42dcf05.md)
  * T1036.003 [Masquerading - non-windows exe running as windows exe](tests/bc15c13f-d121-4b1f-8c7d-28d95854d086.md)
  * T1547.001 [PowerShell Registry RunOnce](tests/eb44f842-0457-4ddc-9b92-c4caa144ac42.md)
  * T1219 [RemotePC Software Execution](tests/fbff3f1f-b0bf-448e-840f-7e1687affdce.md)
  * T1112 [Modify Registry of Local Machine - cmd](tests/282f929a-6bc5-42b8-bd93-960c3ba35afe.md)
  * T1547.001 [Reg Key RunOnce](tests/554cbd88-cde1-4b56-8168-0be552eed9eb.md)
  * T1547.001 [SystemBC Malware-as-a-Service Registry](tests/9dc7767b-30c1-4cc4-b999-50cab5e27891.md)
  * T1218 [InfDefaultInstall.exe .inf Execution](tests/54ad7d5a-a1b5-472c-b6c4-f8090fb2daef.md)
* registry_set_asep_reg_keys_modification_currentversion_nt.yml
  * T1546.008 [Attaches Command Prompt as a Debugger to a List of Target Processes](tests/3309f53e-b22b-4eb6-8fd2-a6cf58b355a9.md)
  * T1546.010 [Install AppInit Shim](tests/a58d9386-3080-4242-ab5f-454c16503d18.md)
  * T1547.004 [Winlogon Shell Key Persistence - PowerShell](tests/bf9f9d65-ee4d-4c3e-a843-777d04f19c38.md)
  * T1546.012 [IFEO Add Debugger](tests/fdda2626-5234-4c90-b163-60849a24c0b8.md)
  * T1546.012 [IFEO Global Flags](tests/46b1f278-c8ee-4aa5-acce-65e77b11f3c1.md)
* registry_set_asep_reg_keys_modification_office.yml
  * T1137.002 [Office Application Startup Test Persistence](tests/c3e35b58-fe1c-480b-b540-7600fb612563.md)
  * T1219 [TeamViewer Files Detected Test on Windows](tests/8ca3b96d-8983-4a7f-b125-fc98cc0a2aa0.md)
* registry_set_blackbyte_ransomware.yml
  * T1112 [BlackByte Ransomware Registry Changes - Powershell](tests/0b79c06f-c788-44a2-8630-d69051f1123d.md)
  * T1112 [BlackByte Ransomware Registry Changes - CMD](tests/4f4e2f9f-6209-4fcf-9b15-3b7455706f5b.md)
* registry_set_bypass_uac_using_delegateexecute.yml
  * T1548.002 [Bypass UAC using sdclt DelegateExecute](tests/3be891eb-4608-4173-87e8-78b494c029b7.md)
* registry_set_bypass_uac_using_eventviewer.yml
  * T1548.002 [Bypass UAC using Event Viewer (PowerShell)](tests/a6ce9acf-842a-4af6-8f79-539be7608e2b.md)
  * T1548.002 [Bypass UAC using Event Viewer (cmd)](tests/5073adf8-9a50-4bd9-b298-a9bd2ead8af9.md)
* registry_set_bypass_uac_using_silentcleanup_task.yml
  * T1548.002 [Bypass UAC using SilentCleanup task](tests/28104f8a-4ff1-4582-bcf6-699dce156608.md)
* registry_set_change_rdp_port.yml
  * T1021.001 [Changing RDP Port to Non Standard Port via Command_Prompt](tests/74ace21e-a31c-4f7d-b540-53e4eb6d1f73.md)
  * T1021.001 [Changing RDP Port to Non Standard Port via Powershell](tests/2f840dd4-8a2e-4f44-beb3-6b2399ea3771.md)
* registry_set_change_security_zones.yml
  * T1112 [Add domain to Trusted sites Zone](tests/cf447677-5a4e-4937-a82c-e47d254afd57.md)
* registry_set_chrome_extension.yml
  * T1133 [Running Chrome VPN Extensions via the Registry 2 vpn extension](tests/4c8db261-a58b-42a6-a866-0a294deedde4.md)
* registry_set_defender_disabled.yml
  * T1562.001 [Disable Defender with Defender Control](tests/178136d8-2778-4d7a-81f3-d517053a4fd6.md)
  * T1562.001 [Tamper with Windows Defender Registry](tests/1b3e0146-a1e5-4c5c-89fb-1bb2ffe8fc45.md)
* registry_set_defender_exclusions.yml
  * T1562.001 [Tamper with Windows Defender Evade Scanning -Extension](tests/315f4be6-2240-4552-b3e1-d1047f5eecea.md)
  * T1562.001 [Tamper with Windows Defender Evade Scanning -Process](tests/a123ce6a-3916-45d6-ba9c-7d4081315c27.md)
  * T1562.001 [Tamper with Windows Defender Evade Scanning -Folder](tests/0b19f4ee-de90-4059-88cb-63c800c683ed.md)
* registry_set_disable_administrative_share.yml
  * T1070.005 [Disable Administrative Share Creation at Startup](tests/99c657aa-ebeb-4179-a665-69288fdd12b8.md)
* registry_set_disable_defender_firewall.yml
  * T1562.004 [Disable Microsoft Defender Firewall via Registry](tests/afedc8c4-038c-4d82-b3e5-623a95f8a612.md)
  * T1562.004 [Disable Microsoft Defender Firewall](tests/88d05800-a5e4-407e-9b53-ece4174f197f.md)
* registry_set_disable_fonction_user.yml
  * T1112 [Disable Windows Registry Tool](tests/ac34b0f7-0f85-4ac0-b93e-3ced2bc69bb8.md)
  * T1112 [Disable Windows Task Manager application](tests/af254e70-dd0e-4de6-9afe-a994d9ea8b62.md)
  * T1112 [Disable Windows Notification Center](tests/c0d6d67f-1f63-42cc-95c0-5fd6b20082ad.md)
  * T1112 [Disable Windows Change Password Feature](tests/d4a6da40-618f-454d-9a9e-26af552aaeb0.md)
  * T1112 [Disable Windows Lock Workstation Feature](tests/3dacb0d2-46ee-4c27-ac1b-f9886bf91a56.md)
  * T1112 [Disable Windows LogOff Button](tests/e246578a-c24d-46a7-9237-0213ff86fb0c.md)
  * T1112 [Disable Windows CMD application](tests/d2561a6d-72bd-408c-b150-13efe1801c2a.md)
  * T1112 [Disable Windows Shutdown Button](tests/6e0d1131-2d7e-4905-8ca5-d6172f05d03d.md)
* registry_set_disable_microsoft_office_security_features.yml
  * T1562.001 [Disable Microsoft Office Security Features](tests/6f5fb61b-4e56-4a3d-a8c3-82e13686c6d7.md)
* registry_set_disable_system_restore.yml
  * T1490 [Disable System Restore Through Registry](tests/66e647d1-8741-4e43-b7c1-334760c2047f.md)
* registry_set_disable_uac_registry.yml
  * T1548.002 [Disable UAC using reg.exe](tests/9e8af564-53ec-407e-aaa8-3cb20c3af7f9.md)
* registry_set_enabling_cor_profiler_env_variables.yml
  * T1574.012 [User scope COR_PROFILER](tests/9d5f89dc-c3a5-4f8a-a4fc-a6ed02e7cb5a.md)
  * T1574.012 [System Scope COR_PROFILER](tests/f373b482-48c8-4ce4-85ed-d40c8b3f7310.md)
* registry_set_etw_disabled.yml
  * T1562.006 [Disable .NET Event Tracing for Windows Via Registry (powershell)](tests/19c07a45-452d-4620-90ed-4c34fffbe758.md)
  * T1562.006 [Disable .NET Event Tracing for Windows Via Registry (cmd)](tests/8a4c33be-a0d3-434a-bee6-315405edbd5b.md)
* registry_set_globalflags_persistence.yml
  * T1546.012 [IFEO Global Flags](tests/46b1f278-c8ee-4aa5-acce-65e77b11f3c1.md)
* registry_set_hidden_extention.yml
  * T1112 [Modify Registry of Current User Profile - cmd](tests/1324796b-d0f6-455a-b4ae-21ffee6aa6b9.md)
* registry_set_hide_file.yml
  * T1564.001 [Hide Files Through Registry](tests/f650456b-bd49-4bc1-ae9d-271b5b9581e7.md)
* registry_set_hide_fonction_user.yml
  * T1112 [Windows Modify Show Compress Color And Info Tip Registry](tests/795d3248-0394-4d4d-8e86-4e8df2a2693f.md)
  * T1112 [Hide Windows Clock Group Policy Feature](tests/8023db1e-ad06-4966-934b-b6a0ae52689e.md)
  * T1112 [Windows HideSCAVolume Group Policy Feature](tests/7f037590-b4c6-4f13-b3cc-e424c5ab8ade.md)
  * T1112 [Windows HideSCAPower Group Policy Feature](tests/8d85a5d8-702f-436f-bc78-fcd9119496fc.md)
  * T1112 [Windows HideSCANetwork Group Policy Feature](tests/3e757ce7-eca0-411a-9583-1c33b8508d52.md)
  * T1112 [Windows HideSCAHealth Group Policy Feature](tests/a4637291-40b1-4a96-8c82-b28f1d73e54e.md)
* registry_set_ie_persistence.yml
  * T1112 [Javascript in registry](tests/15f44ea9-4571-4837-be9e-802431a7bfae.md)
  * T1090.003 [Psiphon](tests/14d55ca0-920e-4b44-8425-37eedd72b173.md)
  * T1220 [MSXSL Bypass using remote files](tests/a7c3ab07-52fb-49c8-ab6d-e9c6d4a0a985.md)
  * T1220 [MSXSL Bypass using local files](tests/ca23bfb2-023f-49c5-8802-e66997de462d.md)
  * T1219 [TeamViewer Files Detected Test on Windows](tests/8ca3b96d-8983-4a7f-b125-fc98cc0a2aa0.md)
* registry_set_install_root_or_ca_certificat.yml
  * T1553.004 [Add Root Certificate to CurrentUser Certificate Store](tests/ca20a3f1-42b5-4e21-ad3f-1049199ec2e0.md)
* registry_set_office_security.yml
  * T1564 [Extract binary files via VBA](tests/6afe288a-8a8b-4d33-a629-8d03ba9dad3a.md)
  * T1204.002 [Office Generic Payload Download](tests/5202ee05-c420-4148-bf5e-fd7f7d24850c.md)
  * T1562.001 [Disable Microsoft Office Security Features](tests/6f5fb61b-4e56-4a3d-a8c3-82e13686c6d7.md)
* registry_set_office_vsto_persistence.yml
  * T1219 [TeamViewer Files Detected Test on Windows](tests/8ca3b96d-8983-4a7f-b125-fc98cc0a2aa0.md)
* registry_set_outlook_registry_webview.yml
  * T1137.004 [Install Outlook Home Page Persistence](tests/7a91ad51-e6d2-4d43-9471-f26362f5738e.md)
* registry_set_outlook_security.yml
  * T1137 [Office Application Startup - Outlook as a C2](tests/bfe6ac15-c50b-4c4f-a186-0fc6b8ba936c.md)
* registry_set_persistence_search_order.yml
  * T1219 [TeamViewer Files Detected Test on Windows](tests/8ca3b96d-8983-4a7f-b125-fc98cc0a2aa0.md)
* registry_set_powershell_as_service.yml
  * T1569.002 [Execute a Command as a Service](tests/2382dee2-a75f-49aa-9378-f52df6ed3fb1.md)
* registry_set_powershell_in_run_keys.yml
  * T1547.001 [SystemBC Malware-as-a-Service Registry](tests/9dc7767b-30c1-4cc4-b999-50cab5e27891.md)
* registry_set_powershell_logging_disabled.yml
  * T1112 [Windows Powershell Logging Disabled](tests/95b25212-91a7-42ff-9613-124aca6845a8.md)
* registry_set_rdp_registry_modification.yml
  * T1078.001 [Enable Guest account with RDP capability and admin privileges](tests/99747561-ed8d-47f2-9c91-1e5fde1ed6e0.md)
* registry_set_rdp_settings_hijack.yml
  * T1078.001 [Enable Guest account with RDP capability and admin privileges](tests/99747561-ed8d-47f2-9c91-1e5fde1ed6e0.md)
* registry_set_set_nopolicies_user.yml
  * T1112 [Activate Windows NoTrayContextMenu Group Policy Feature](tests/4d72d4b1-fa7b-4374-b423-0fe326da49d2.md)
  * T1112 [Activate Windows NoControlPanel Group Policy Feature](tests/a450e469-ba54-4de1-9deb-9023a6111690.md)
  * T1112 [Activate Windows NoFind Group Policy Feature](tests/ffbb407e-7f1d-4c95-b22e-548169db1fbd.md)
  * T1112 [Activate Windows NoDesktop Group Policy Feature](tests/93386d41-525c-4a1b-8235-134a628dee17.md)
  * T1112 [Activate Windows NoFileMenu Group Policy Feature](tests/5e27bdb4-7fd9-455d-a2b5-4b4b22c9dea4.md)
  * T1112 [Disable Windows LogOff Button](tests/e246578a-c24d-46a7-9237-0213ff86fb0c.md)
  * T1112 [Activate Windows NoPropertiesMyDocuments Group Policy Feature](tests/20fc9daa-bd48-4325-9aff-81b967a84b1d.md)
  * T1112 [Activate Windows NoClose Group Policy Feature](tests/12f50e15-dbc6-478b-a801-a746e8ba1723.md)
  * T1112 [Activate Windows NoRun Group Policy Feature](tests/d49ff3cc-8168-4123-b5b3-f057d9abbd55.md)
  * T1112 [Activate Windows NoSetTaskbar Group Policy Feature](tests/d29b7faf-7355-4036-9ed3-719bd17951ed.md)
* registry_set_set_servicedll.yml
  * T1543.003 [TinyTurla backdoor service w64time](tests/ef0581fd-528e-4662-87bc-4c2affb86940.md)
* registry_set_shim_databases_persistence.yml
  * T1546.011 [Registry key creation and/or modification events for SDB](tests/9b6a06f9-ab5e-4e8d-8289-1df4289db02f.md)
* registry_set_susp_run_key_img_folder.yml
  * T1036.003 [Masquerading - non-windows exe running as windows exe](tests/bc15c13f-d121-4b1f-8c7d-28d95854d086.md)
* registry_set_wdigest_enable_uselogoncredential.yml
  * T1112 [Modify registry to store logon credentials](tests/c0413fb5-33e2-40b7-9b6f-60b29f4a7a18.md)
* registry_set_winlogon_notify_key.yml
  * T1547.004 [Winlogon Notify Key Logon Persistence - PowerShell](tests/d40da266-e073-4e5a-bb8b-2b385023e5f9.md)
* sysmon_accessing_winapi_in_powershell_credentials_dumping.yml
  * T1036.003 [Masquerading as Windows LSASS process](tests/5ba5a3d1-cf3c-4499-968a-a93155d1f717.md)
  * T1134.002 [Access Token Manipulation](tests/dbf4f5a9-b8e0-46a3-9841-9ad71247239e.md)
  * T1003.002 [PowerDump Hashes and Usernames from Registry](tests/804f28fc-68fc-40da-b5a2-e9d0bce5c193.md)
  * T1057 [Process Discovery - Get-Process](tests/3b3809b6-a54b-4f5b-8aff-cb51f2e97b34.md)
  * T1003.001 [Powershell Mimikatz](tests/66fb0bc1-3c3f-47e9-a298-550ecfefacbc.md)
  * T1003.001 [Dump LSASS.exe Memory using Out-Minidump.ps1](tests/6502c8f0-b775-4dbd-9193-1298f56b6781.md)
* sysmon_powershell_code_injection.yml
  * T1134.004 [Parent PID Spoofing using PowerShell](tests/069258f4-2162-46e9-9a25-c9c6c56150d2.md)
  * T1018 [Get-DomainController with PowerView](tests/b9d2e8ca-5520-4737-8076-4f08913da2c4.md)
* sysmon_suspicious_remote_thread.yml
  * T1134.004 [Parent PID Spoofing using PowerShell](tests/069258f4-2162-46e9-9a25-c9c6c56150d2.md)
  * T1018 [Get-DomainController with PowerView](tests/b9d2e8ca-5520-4737-8076-4f08913da2c4.md)
* sysmon_wmi_event_subscription.yml
  * T1546.003 [Persistence via WMI Event Subscription](tests/3c64f177-28e2-49eb-a799-d767b24dd1e0.md)
* win_alert_mimikatz_keywords.yml
  * T1207 [DCShadow (Active Directory)](tests/0f4c5eb0-98a0-4496-9c3d-656b4f2bc8f6.md)
  * T1550.003 [Mimikatz Kerberos Ticket Attack](tests/dbf38128-7ba7-4776-bedf-cc2eed432098.md)
  * T1134.005 [Injection SID-History with mimikatz](tests/6bef32e5-9456-4072-8f14-35566fb85401.md)
  * T1003.006 [Run DSInternals Get-ADReplAccount](tests/a0bced08-3fc5-4d8b-93b7-e8344739376e.md)
  * T1550.003 [Rubeus Kerberos Pass The Ticket](tests/a2fc4ec5-12c6-4fb4-b661-961f23f359cb.md)
  * T1550.002 [Mimikatz Pass the Hash](tests/ec23cef9-27d9-46e4-a68d-6f75f7b86908.md)
  * T1003.001 [Offline Credential Theft With Mimikatz](tests/453acf13-1dbd-47d7-b28a-172ce9228023.md)
  * T1558.002 [Crafting Active Directory silver tickets with mimikatz](tests/385e59aa-113e-4711-84d9-f637aef01f2c.md)
  * T1550.002 [crackmapexec Pass the Hash](tests/eb05b028-16c8-4ad8-adea-6f5b219da9a9.md)
  * T1558.001 [Crafting Active Directory golden tickets with Rubeus](tests/e42d33cd-205c-4acf-ab59-a9f38f6bad9c.md)
  * T1558.001 [Crafting Active Directory golden tickets with mimikatz](tests/9726592a-dabc-4d4d-81cd-44070008b3af.md)
  * T1550.002 [Invoke-WMIExec Pass the Hash](tests/f8757545-b00a-4e4e-8cfb-8cfb961ee713.md)
  * T1059.001 [Mimikatz](tests/f3132740-55bc-48c4-bcc0-758a459cd027.md)
* win_av_relevant_match.yml
  * T1550.002 [crackmapexec Pass the Hash](tests/eb05b028-16c8-4ad8-adea-6f5b219da9a9.md)
* win_builtin_remove_application.yml
  * T1047 [Application uninstall using WMIC](tests/c510d25b-1667-467d-8331-a56d3e9bc4ff.md)
* win_defender_tamper_protection_trigger.yml
  * T1562.001 [Disable Defender with Defender Control](tests/178136d8-2778-4d7a-81f3-d517053a4fd6.md)
* win_defender_threat.yml
  * T1562.001 [Disable Defender with Defender Control](tests/178136d8-2778-4d7a-81f3-d517053a4fd6.md)
* win_disable_event_logging.yml
  * T1562.002 [Clear Windows Audit Policy Config](tests/913c0e4e-4b37-4b78-ad0b-90e7b25010f6.md)
* win_event_log_cleared.yml
  * T1070.001 [Delete System Logs Using Clear-EventLog](tests/b13e9306-3351-4b4b-a6e8-477358b0b498.md)
  * T1070.001 [Clear Event Logs via VBA](tests/1b682d84-f075-4f93-9a89-8a8de19ffd6e.md)
* win_overpass_the_hash.yml
  * T1558.001 [Crafting Active Directory golden tickets with Rubeus](tests/e42d33cd-205c-4acf-ab59-a9f38f6bad9c.md)
  * T1558.001 [Crafting Active Directory golden tickets with mimikatz](tests/9726592a-dabc-4d4d-81cd-44070008b3af.md)
* win_pass_the_hash_2.yml
  * T1558.001 [Crafting Active Directory golden tickets with Rubeus](tests/e42d33cd-205c-4acf-ab59-a9f38f6bad9c.md)
  * T1558.001 [Crafting Active Directory golden tickets with mimikatz](tests/9726592a-dabc-4d4d-81cd-44070008b3af.md)
* win_susp_eventlog_cleared.yml
  * T1070.001 [Delete System Logs Using Clear-EventLog](tests/b13e9306-3351-4b4b-a6e8-477358b0b498.md)
  * T1070.001 [Clear Event Logs via VBA](tests/1b682d84-f075-4f93-9a89-8a8de19ffd6e.md)
* win_susp_logon_explicit_credentials.yml
  * T1110.001 [Brute Force Credentials of single Active Directory domain user via LDAP against domain controller (NTLM or Kerberos)](tests/c2969434-672b-4ec8-8df0-bbb91f40e250.md)
* win_susp_service_installation_folder.yml
  * T1219 [Ammyy Admin Software Execution](tests/0ae9e327-3251-465a-a53b-485d4e3f58fa.md)
* win_system_susp_eventlog_cleared.yml
  * T1070.001 [Clear Logs](tests/e6abb60e-26b8-41da-8aae-0c35174b0967.md)
  * T1070.001 [Delete System Logs Using Clear-EventLog](tests/b13e9306-3351-4b4b-a6e8-477358b0b498.md)
  * T1070.001 [Clear Event Logs via VBA](tests/1b682d84-f075-4f93-9a89-8a8de19ffd6e.md)
* win_tool_psexec.yml
  * T1562.006 [Disable Powershell ETW Provider - Windows](tests/6f118276-121d-4c09-bb58-a8fb4a72ee84.md)
* win_wmi_persistence.yml
  * T1546.003 [Persistence via WMI Event Subscription](tests/3c64f177-28e2-49eb-a799-d767b24dd1e0.md)