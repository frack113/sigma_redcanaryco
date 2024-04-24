
[back](../index.md)

Find sigma rule :x: 

# Attack: Pre-OS Boot: System Firmware 

Adversaries may modify system firmware to persist on systems.The BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) or Extensible Firmware Interface (EFI) are examples of system firmware that operate as the software interface between the operating system and hardware of a computer. (Citation: Wikipedia BIOS) (Citation: Wikipedia UEFI) (Citation: About UEFI)

System firmware like BIOS and (U)EFI underly the functionality of a computer and may be modified by an adversary to perform or assist in malicious activity. Capabilities exist to overwrite the system firmware, which may give sophisticated adversaries a means to install malicious firmware updates as a means of persistence on a system that may be difficult to detect.

# MITRE
## Tactic
  - persistence
  - defense-evasion


## technique
  - T1542.001


# Test : UEFI Persistence via Wpbbin.exe File Creation
## OS
  - windows


## Description:
Creates Wpbbin.exe in %systemroot%. This technique can be used for UEFI-based pre-OS boot persistence mechanisms.
- https://grzegorztworek.medium.com/using-uefi-to-inject-executable-files-into-bitlocker-protected-drives-8ff4ca59c94c
- http://download.microsoft.com/download/8/a/2/8a2fb72d-9b96-4e2d-a559-4a27cf905a80/windows-platform-binary-table.docx
- https://github.com/tandasat/WPBT-Builder


## Executor
powershell

# Sigma Rule


[back](../index.md)
