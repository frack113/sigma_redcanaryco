
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: Data Encoding: Standard Encoding 

Adversaries may encode data with a standard data encoding system to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system that adheres to existing protocol specifications. Common data encoding schemes include ASCII, Unicode, hexadecimal, Base64, and MIME.(Citation: Wikipedia Binary-to-text Encoding) (Citation: Wikipedia Character Encoding) Some data encoding systems may also result in data compression, such as gzip.

# MITRE
## Tactic
  - command-and-control


## technique
  - T1132.001


# Test : XOR Encoded data.
## OS
  - windows


## Description:
XOR encodes the data with a XOR key.
Reference - https://gist.github.com/loadenmb/8254cee0f0287b896a05dcdc8a30042f


## Executor
powershell

# Sigma Rule
 - proc_creation_win_susp_web_request_cmd.yml (id: 9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d)

 - proc_creation_win_powershell_xor_commandline.yml (id: bb780e0c-16cf-4383-8383-1e5471db6cf9)

 - posh_ps_web_request.yml (id: 1139d2e2-84b1-4226-b445-354492eba8ba)

 - posh_ps_upload.yml (id: d2e3f2f6-7e09-4bf2-bc5d-90186809e7fb)

 - net_connection_win_powershell_network_connection.yml (id: 1f21ec3f-810d-4b0e-8045-322202e22b4b)



[back](../index.md)
