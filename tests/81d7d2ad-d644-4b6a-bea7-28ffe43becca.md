
[back](../index.md)

Find sigma rule :x: 

# Attack: Keylogging 

Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) efforts are not effective, and may require an adversary to intercept keystrokes on a system for a substantial period of time before credentials can be successfully captured.

Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes.(Citation: Adventures of a Keystroke) Some methods include:

* Hooking API callbacks used for processing keystrokes. Unlike [Credential API Hooking](https://attack.mitre.org/techniques/T1056/004), this focuses solely on API functions intended for processing keystroke data.
* Reading raw keystroke data from the hardware buffer.
* Windows Registry modifications.
* Custom drivers.
* [Modify System Image](https://attack.mitre.org/techniques/T1601) may provide adversaries with hooks into the operating system of network devices to read raw keystrokes for login sessions.(Citation: Cisco Blog Legacy Device Attacks) 

# MITRE
## Tactic
  - credential-access
  - collection


## technique
  - T1056.001


# Test : SSHD PAM keylogger
## OS
  - linux


## Description:
Linux PAM (Pluggable Authentication Modules) is used in sshd authentication. The Linux audit tool auditd can use the pam_tty_audit module to enable auditing of TTY input and capture all keystrokes in a ssh session and place them in the /var/log/audit/audit.log file after the session closes.


# Sigma Rule


[back](../index.md)
