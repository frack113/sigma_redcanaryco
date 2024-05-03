
[back](../index.md)

Find sigma rule :x: 

# Attack: OS Credential Dumping: LSASS Memory 

Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct [Lateral Movement](https://attack.mitre.org/tactics/TA0008) using [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550).

As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.

For example, on the target host use procdump:

* <code>procdump -ma lsass.exe lsass_dump</code>

Locally, mimikatz can be run using:

* <code>sekurlsa::Minidump lsassdump.dmp</code>
* <code>sekurlsa::logonPasswords</code>

Built-in Windows tools such as `comsvcs.dll` can also be used:

* <code>rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump PID  lsass.dmp full</code>(Citation: Volexity Exchange Marauder March 2021)(Citation: Symantec Attacks Against Government Sector)

Similar to [Image File Execution Options Injection](https://attack.mitre.org/techniques/T1546/012), the silent process exit mechanism can be abused to create a memory dump of `lsass.exe` through Windows Error Reporting (`WerFault.exe`).(Citation: Deep Instinct LSASS)

Windows Security Support Provider (SSP) DLLs are loaded into LSASS process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages</code> and <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages</code>. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.(Citation: Graeber 2014)

The following SSPs can be used to access credentials:

* Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package.
* Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges.(Citation: TechNet Blogs Credential Protection)
* Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later.
* CredSSP:  Provides SSO and Network Level Authentication for Remote Desktop Services.(Citation: TechNet Blogs Credential Protection)


# MITRE
## Tactic
  - credential-access


## technique
  - T1003.001


# Test : Dump LSASS.exe Memory through Silent Process Exit
## OS
  - windows


## Description:
WerFault.exe (Windows Error Reporting process that handles process crashes) can be abused to create a 
memory dump of lsass.exe, in a directory of your choice. This method relies on a mechanism 
introduced in Windows 7 called Silent Process Exit, which provides the ability to trigger
specific actions for a monitored process in one of two scenarios; either the process terminates
itself by calling ExitProcess(), or another process terminates it via the TerminateProcess() API. 
The major advantage of this technique is that it does not cause lsass.exe to crash, and since 
WerFault.exe is used to create file dumps all the time (not just lsass.exe), this method provides 
the added advantage of going undetected. WerFault.exe is a process known for dumping every crashing process, 
from an attacker standpoint this is appealing as their illicit credential extraction will 
appear benign because from a defender’s viewpoint it’s within the realm of normal activity.

Upon successful execution, you should find the dump file in directory of your choice or "%temp%\SilentProcessExit" by default.


## Executor
command_prompt

# Sigma Rule


[back](../index.md)
