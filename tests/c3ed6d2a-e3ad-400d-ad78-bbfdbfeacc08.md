[back](../index.md)

Cover by sigma :x: 

# Attack: Standard Encoding

 Adversaries may encode data with a standard data encoding system to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system that adheres to existing protocol specifications. Common data encoding schemes include ASCII, Unicode, hexadecimal, Base64, and MIME.(Citation: Wikipedia Binary-to-text Encoding) (Citation: Wikipedia Character Encoding) Some data encoding systems may also result in data compression, such as gzip.

# MITRE
## Tactic
  - command-and-control

## technique
  - T1132.001

# Test : XOR Encoded data.

## OS

 ['windows']

## Description:

 XOR encodes the data with a XOR key.
Reference - https://gist.github.com/loadenmb/8254cee0f0287b896a05dcdc8a30042f


# Sigma Rule
