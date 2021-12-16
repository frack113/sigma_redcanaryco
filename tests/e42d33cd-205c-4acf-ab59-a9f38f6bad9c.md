
[back](../index.md)
Find sigma rule :x: 

# Attack: Golden Ticket 

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


# Sigma Rule


[back](../index.md)
