
[back](../index.md)

Find sigma rule :heavy_check_mark: 

# Attack: Audio Capture 

An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information.

Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture audio. Audio files may be written to disk and exfiltrated later.

# MITRE
## Tactic
  - collection


## technique
  - T1123


# Test : Registry artefact when application use microphone
## OS
  - windows


## Description:
[can-you-track-processes-accessing-the-camera-and-microphone](https://svch0st.medium.com/can-you-track-processes-accessing-the-camera-and-microphone-7e6885b37072)


## Executor
command_prompt

# Sigma Rule
 - registry_event_susp_mic_cam_access.yml (id: 62120148-6b7a-42be-8b91-271c04e281a3)



[back](../index.md)
