
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay 

By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials. 

Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. NBT-NS identifies systems on a local network by their NetBIOS name. (Citation: Wikipedia LLMNR) (Citation: TechNet NetBIOS)

Adversaries can spoof an authoritative source for name resolution on a victim network by responding to LLMNR (UDP 5355)/NBT-NS (UDP 137) traffic as if they know the identity of the requested host, effectively poisoning the service so that the victims will communicate with the adversary controlled system. If the requested host belongs to a resource that requires identification/authentication, the username and NTLMv2 hash will then be sent to the adversary controlled system. The adversary can then collect the hash information sent over the wire through tools that monitor the ports for traffic or through [Network Sniffing](https://attack.mitre.org/techniques/T1040) and crack the hashes offline through [Brute Force](https://attack.mitre.org/techniques/T1110) to obtain the plaintext passwords. In some cases where an adversary has access to a system that is in the authentication path between systems or when automated scans that use credentials attempt to authenticate to an adversary controlled system, the NTLMv2 hashes can be intercepted and relayed to access and execute code against a target system. The relay step can happen in conjunction with poisoning but may also be independent of it. (Citation: byt3bl33d3r NTLM Relaying)(Citation: Secure Ideas SMB Relay)

Several tools exist that can be used to poison name services within local networks such as NBNSpoof, Metasploit, and [Responder](https://attack.mitre.org/software/S0174). (Citation: GitHub NBNSpoof) (Citation: Rapid7 LLMNR Spoofer) (Citation: GitHub Responder)

# MITRE
## Tactic
  - credential-access
  - collection


## technique
  - T1557.001


# Test : LLMNR Poisoning with Inveigh (PowerShell)
## OS
  - windows


## Description:
Inveigh conducts spoofing attacks and hash/credential captures through both packet sniffing and protocol specific listeners/sockets. This Atomic will run continuously until you cancel it or it times out.

## Executor
powershell

# Sigma Rule
 - proc_creation_win_powershell_non_interactive_execution.yml (id: f4bbd493-b796-416e-bbf2-121235348529)

 - proc_creation_win_susp_web_request_cmd_and_cmdlets.yml (id: 9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d)

 - posh_ps_web_request_cmd_and_cmdlets.yml (id: 1139d2e2-84b1-4226-b445-354492eba8ba)

 - posh_ps_malicious_commandlets.yml (id: 89819aa4-bbd6-46bc-88ec-c7f7fe30efa6)

 - posh_ps_malicious_keywords.yml (id: f62176f3-8128-4faa-bf6c-83261322e5eb)

 - posh_ps_susp_networkcredential.yml (id: 1883444f-084b-419b-ac62-e0d0c5b3693f)

 - posh_ps_accessing_win_api.yml (id: 03d83090-8cba-44a0-b02f-0b756a050306)

 - net_connection_win_powershell_network_connection.yml (id: 1f21ec3f-810d-4b0e-8045-322202e22b4b)

 - net_connection_win_binary_susp_com.yml (id: e0f8ab85-0ac9-423b-a73a-81b3c7b1aa97)



[back](../index.md)
