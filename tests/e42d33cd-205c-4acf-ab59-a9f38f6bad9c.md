
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: Steal or Forge Kerberos Tickets: Golden Ticket 

Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket.(Citation: AdSecurity Kerberos GT Aug 2015) Golden tickets enable adversaries to generate authentication material for any account in Active Directory.(Citation: CERT-EU Golden Ticket Protection) 

Using a golden ticket, adversaries are then able to request ticket granting service (TGS) tickets, which enable access to specific resources. Golden tickets require adversaries to interact with the Key Distribution Center (KDC) in order to obtain TGS.(Citation: ADSecurity Detecting Forged Tickets)

The KDC service runs all on domain controllers that are part of an Active Directory domain. KRBTGT is the Kerberos Key Distribution Center (KDC) service account and is responsible for encrypting and signing all Kerberos tickets.(Citation: ADSecurity Kerberos and KRBTGT) The KRBTGT password hash may be obtained using [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) and privileged access to a domain controller.

# MITRE
## Tactic
  - credential-access


## technique
  - T1558.001


# Test : Crafting Active Directory golden tickets with Rubeus
## OS
  - windows


## Description:
Once the hash of the special krbtgt user is retrieved it is possible to craft Kerberos Ticket Granting Ticket impersonating any user in the Active Directory domain.
This test crafts a Golden Ticket and then performs an SMB request with it for the SYSVOL share, thus triggering a service ticket request (event ID 4769).
The generated ticket is injected in a new empty Windows session and discarded after, so it does not pollute the current Windows session.


## Executor
powershell

# Sigma Rule
 - win_alert_mimikatz_keywords.yml (id: 06d71506-7beb-4f22-8888-e2e5e2ca7fd8)

 - proc_creation_win_hack_rubeus.yml (id: 7ec2c172-dceb-4c10-92c9-87c1881b7e18)

 - file_event_win_detect_powerup_dllhijacking.yml (id: 602a1f13-c640-4d73-b053-be9a2fa58b96)

 - win_overpass_the_hash.yml (id: 192a0330-c20b-4356-90b6-7b7049ae0b87)

 - win_pass_the_hash_2.yml (id: 8eef149c-bd26-49f2-9e5a-9b00e3af499b)



[back](../index.md)
