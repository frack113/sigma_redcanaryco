
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: LSASS Memory 

Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct [Lateral Movement](https://attack.mitre.org/tactics/TA0008) using [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550).

As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.

For example, on the target host use procdump:

* <code>procdump -ma lsass.exe lsass_dump</code>

Locally, mimikatz can be run using:

* <code>sekurlsa::Minidump lsassdump.dmp</code>
* <code>sekurlsa::logonPasswords</code>


Windows Security Support Provider (SSP) DLLs are loaded into LSSAS process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages</code> and <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages</code>. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.(Citation: Graeber 2014)

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


# Test : Powershell Mimikatz
## OS
  - windows


## Description:
Dumps credentials from memory via Powershell by invoking a remote mimikatz script.
If Mimikatz runs successfully you will see several usernames and hashes output to the screen.
Common failures include seeing an \"access denied\" error which results when Anti-Virus blocks execution. 
Or, if you try to run the test without the required administrative privleges you will see this error near the bottom of the output to the screen "ERROR kuhl_m_sekurlsa_acquireLSA"


## Executor
powershell

# Sigma Rule
 - posh_ps_nishang_malicious_commandlets.yml (id: f772cee9-b7c2-4cb2-8f07-49870adc02e0)

 - posh_ps_malicious_keywords.yml (id: f62176f3-8128-4faa-bf6c-83261322e5eb)

 - posh_ps_malicious_commandlets.yml (id: 89819aa4-bbd6-46bc-88ec-c7f7fe30efa6)

 - posh_pm_suspicious_invocation_specific.yml (id: 8ff28fdd-e2fa-4dfa-aeda-ef3d61c62090)

 - posh_ps_suspicious_keywords.yml (id: 1f49f2ab-26bc-48b3-96cc-dcffbc93eadf)

 - posh_ps_accessing_win_api.yml (id: 03d83090-8cba-44a0-b02f-0b756a050306)

 - sysmon_accessing_winapi_in_powershell_credentials_dumping.yml (id: 3f07b9d1-2082-4c56-9277-613a621983cc)



[back](../index.md)
