# Welcome to my sigma redcannary cover projet

## Purpose

Knowing which rule should trigger when running a [redcannary test](https://github.com/redcanaryco/atomic-red-team)

When run a test noisy many rules can trigger too...

<p align="center" width="100%">
    <img width="33%" src="./png/allright.jpg "> 
</p>

## Tests



### T1560.002
[Compressing data using zipfile in Python (Linux)](tests/001a042b-859f-44d9-bf81-fd1c4e2200b0.md) ['linux'] (sigma rule :x:)

[Compressing data using GZip in Python (Linux)](tests/391f5298-b12d-4636-8482-35d9c17d53a8.md) ['linux'] (sigma rule :x:)

[Compressing data using bz2 in Python (Linux)](tests/c75612b2-9de0-4d7c-879c-10d7b077072d.md) ['linux'] (sigma rule :x:)

[Compressing data using tarfile in Python (Linux)](tests/e86f1b4b-fcc1-4a2a-ae10-b49da01458db.md) ['linux'] (sigma rule :x:)


### T1553.005
[Mount ISO image](tests/002cca30-4778-4891-878a-aaffcfa502fa.md) ['windows'] (sigma rule :x:)

[Mount an ISO image and run executable from the ISO](tests/42f22b00-0242-4afc-a61b-0da05041f9cc.md) ['windows'] (sigma rule :x:)

[Remove the Zone.Identifier alternate data stream](tests/64b12afc-18b8-4d3f-9eab-7f6cae7c73f9.md) ['windows'] (sigma rule :x:)


### T1564.004
[Create ADS PowerShell](tests/0045ea16-ed3c-4d4c-a9ee-15e44d1560d1.md) ['windows'] (sigma rule :x:)

[Create ADS command prompt](tests/17e7637a-ddaf-4a82-8622-377e20de8fdb.md) ['windows'] (sigma rule :x:)

[Store file in Alternate Data Stream (ADS)](tests/2ab75061-f5d5-4c1a-b666-ba2a50df5b02.md) ['windows'] (sigma rule :x:)

[Alternate Data Streams (ADS)](tests/8822c3b0-d9f9-4daf-a043-49f4602364f4.md) ['windows'] (sigma rule :x:)


### T1140
[Hex decoding with shell utilities](tests/005943f9-8dd5-4349-8b46-0313c0a9f973.md) ['linux', 'macos'] (sigma rule :x:)

[Base64 decoding with Python](tests/356dc0e8-684f-4428-bb94-9313998ad608.md) ['linux', 'macos'] (sigma rule :x:)

[Base64 decoding with Perl](tests/6604d964-b9f6-4d4b-8ce8-499829a14d0a.md) ['linux', 'macos'] (sigma rule :x:)

[Certutil Rename and Decode](tests/71abc534-3c05-4d0c-80f7-cbe93cb2aa94.md) ['windows'] (sigma rule :x:)

[Base64 decoding with shell utilities](tests/b4f6a567-a27a-41e5-b8ef-ac4b4008bb7e.md) ['linux', 'macos'] (sigma rule :x:)

[Deobfuscate/Decode Files Or Information](tests/dc6fe391-69e6-4506-bd06-ea5eeb4082f8.md) ['windows'] (sigma rule :x:)


### T1047
[WMI Execute rundll32](tests/00738d2a-4651-4d76-adf2-c43a41dfb243.md) ['windows'] (sigma rule :x:)

[WMI Reconnaissance List Remote Services](tests/0fd48ef7-d890-4e93-a533-f7dedd5191d3.md) ['windows'] (sigma rule :x:)

[Create a Process using obfuscated Win32_Process](tests/10447c83-fc38-462a-a936-5102363b1c43.md) ['windows'] (sigma rule :x:)

[WMI Reconnaissance Processes](tests/5750aa16-0e59-4410-8b9a-8a47ca2788e2.md) ['windows'] (sigma rule :x:)

[WMI Reconnaissance Software](tests/718aebaa-d0e0-471a-8241-c5afa69c7414.md) ['windows'] (sigma rule :x:)

[Create a Process using WMI Query and an Encoded Command](tests/7db7a7f9-9531-4840-9b30-46220135441c.md) ['windows'] (sigma rule :x:)

[WMI Execute Remote Process](tests/9c8ef159-c666-472f-9874-90c8d60d136b.md) ['windows'] (sigma rule :x:)

[WMI Execute Local Process](tests/b3bdfc91-b33e-4c6d-a5c8-d64bee0276b3.md) ['windows'] (sigma rule :x:)

[WMI Reconnaissance Users](tests/c107778c-dcf5-47c5-af2e-1d058a3df3ea.md) ['windows'] (sigma rule :x:)


### T1218.005
[Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement](tests/007e5672-2088-4853-a562-7490ddc19447.md) ['windows'] (sigma rule :x:)

[Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject](tests/1483fab9-4f52-4217-a9ce-daa9d7747cae.md) ['windows'] (sigma rule :x:)

[Invoke HTML Application - Direct download from URI](tests/39ceed55-f653-48ac-bd19-aceceaf525db.md) ['windows'] (sigma rule :x:)

[Invoke HTML Application - Jscript Engine Simulating Double Click](tests/58a193ec-131b-404e-b1ca-b35cf0b18c33.md) ['windows'] (sigma rule :x:)

[Mshta used to Execute PowerShell](tests/8707a805-2b76-4f32-b1c0-14e558205772.md) ['windows'] (sigma rule :x:)

[Mshta executes VBScript to execute malicious command](tests/906865c3-e05f-4acc-85c4-fbc185455095.md) ['windows'] (sigma rule :x:)

[Invoke HTML Application - Simulate Lateral Movement over UNC Path](tests/b8a8bdb2-7eae-490d-8251-d5e0295b2362.md) ['windows'] (sigma rule :x:)

[Mshta Executes Remote HTML Application (HTA)](tests/c4b97eeb-5249-4455-a607-59f95485cb45.md) ['windows'] (sigma rule :x:)

[Invoke HTML Application - JScript Engine with Inline Protocol Handler](tests/d3eaaf6a-cdb1-44a9-9ede-b6c337d0d840.md) ['windows'] (sigma rule :x:)

[Invoke HTML Application - JScript Engine with Rundll32 and Inline Protocol Handler](tests/e7e3a525-7612-4d68-a5d3-c4649181b8af.md) ['windows'] (sigma rule :x:)


### T1105
[sftp remote file copy (pull)](tests/0139dba1-f391-405e-a4f5-f3989f2c88ef.md) ['linux', 'macos'] (sigma rule :x:)

[rsync remote file copy (push)](tests/0fc6e977-cb12-44f6-b263-2824ba917409.md) ['linux', 'macos'] (sigma rule :x:)

[Download a file with IMEWDBLD.exe](tests/1a02df58-09af-4064-a765-0babe1a0d1e2.md) ['windows'] (sigma rule :x:)

[Curl Download File](tests/2b080b99-0deb-4d51-af0f-833d37c4ca6a.md) ['windows'] (sigma rule :x:)

[OSTAP Worming Activity](tests/2ca61766-b456-4fcf-a35a-1233685e1cad.md) ['windows'] (sigma rule :x:)

[rsync remote file copy (pull)](tests/3180f7d5-52c0-4493-9ea0-e3431a84773f.md) ['linux', 'macos'] (sigma rule :x:)

[Windows - PowerShell Download](tests/42dc4460-9aa6-45d3-b1a6-3955d34e1fe8.md) ['windows'] (sigma rule :x:)

[File Download via PowerShell](tests/54a4daf1-71df-4383-9ba7-f1a295d8b6d2.md) ['windows'] (sigma rule :x:)

[File download with finger.exe on Windows](tests/5f507e45-8411-4f99-84e7-e38530c45d01.md) ['windows'] (sigma rule :x:)

[Curl Upload File](tests/635c9a38-6cbf-47dc-8615-3810bc1167cf.md) ['windows'] (sigma rule :x:)

[Download a File with Windows Defender MpCmdRun.exe](tests/815bef8b-bf91-4b67-be4c-abe4c2a94ccc.md) ['windows'] (sigma rule :x:)

[scp remote file copy (push)](tests/83a49600-222b-4866-80a0-37736ad29344.md) ['linux', 'macos'] (sigma rule :x:)

[Windows - BITSAdmin BITS Download](tests/a1921cd3-9a2d-47d5-a891-f1d0f2a7a31b.md) ['windows'] (sigma rule :x:)

[scp remote file copy (pull)](tests/b9d22b9a-9778-4426-abf0-568ea64e9c33.md) ['linux', 'macos'] (sigma rule :x:)

[whois file download](tests/c99a829f-0bb8-4187-b2c6-d47d1df74cab.md) ['linux', 'macos'] (sigma rule :x:)

[certutil download (urlcache)](tests/dd3b61dd-7bbc-48cd-ab51-49ad1a776df0.md) ['windows'] (sigma rule :heavy_check_mark:)

[sftp remote file copy (push)](tests/f564c297-7978-4aa9-b37a-d90477feea4e.md) ['linux', 'macos'] (sigma rule :x:)

[svchost writing a file to a UNC path](tests/fa5a2759-41d7-4e13-a19c-e8f28a53566f.md) ['windows'] (sigma rule :x:)

[certutil download (verifyctl)](tests/ffd492e3-0455-4518-9fb1-46527c9f241b.md) ['windows'] (sigma rule :x:)


### T1136.001
[Create a user account on a MacOS system](tests/01993ba5-1da3-4e15-a719-b690d4f0f0b2.md) ['macos'] (sigma rule :x:)

[Create a user account on a Linux system](tests/40d8eabd-e394-46f6-8785-b9bfa1d011d2.md) ['linux'] (sigma rule :x:)

[Create a new user in a command prompt](tests/6657864e-0323-4206-9344-ac9cd7265a4f.md) ['windows'] (sigma rule :x:)

[Create a new user in Linux with `root` UID and GID.](tests/a1040a30-d28b-4eda-bd99-bb2861a4616c.md) ['linux'] (sigma rule :x:)

[Create a new user in PowerShell](tests/bc8be0ac-475c-4fbf-9b1d-9fffd77afbde.md) ['windows'] (sigma rule :x:)

[Create a new Windows admin user](tests/fda74566-a604-4581-a4cc-fbbe21d66559.md) ['windows'] (sigma rule :x:)


### T1560.001
[Compress Data and lock with password for Exfiltration with winzip](tests/01df0353-d531-408d-a0c5-3161bf822134.md) ['windows'] (sigma rule :heavy_check_mark:)

[Data Encrypted with zip and gpg symmetric](tests/0286eb44-e7ce-41a0-b109-3da516e05a5f.md) ['macos', 'linux'] (sigma rule :x:)

[Compress Data for Exfiltration With Rar](tests/02ea31cb-3b4c-4a2d-9bf1-e4e70ebcf5d0.md) ['windows'] (sigma rule :heavy_check_mark:)

[Data Compressed - nix - tar Folder or File](tests/7af2b51e-ad1c-498c-aca8-d3290c19535a.md) ['linux', 'macos'] (sigma rule :x:)

[Compress Data and lock with password for Exfiltration with winrar](tests/8dd61a55-44c6-43cc-af0c-8bdda276860c.md) ['windows'] (sigma rule :heavy_check_mark:)

[Data Compressed - nix - zip](tests/c51cec55-28dd-4ad2-9461-1eacbc82c3a0.md) ['linux', 'macos'] (sigma rule :x:)

[Data Compressed - nix - gzip Single File](tests/cde3c2af-3485-49eb-9c1f-0ed60e9cc0af.md) ['linux', 'macos'] (sigma rule :x:)

[Compress Data and lock with password for Exfiltration with 7zip](tests/d1334303-59cb-4a03-8313-b3e24d02c198.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1095
[ICMP C2](tests/0268e63c-e244-42db-bef7-72a9e59fc1fc.md) ['windows'] (sigma rule :x:)

[Powercat C2](tests/3e0e0e7f-6aa2-4a61-b61d-526c2cc9330e.md) ['windows'] (sigma rule :x:)

[Netcat C2](tests/bcf0d1c1-3f6a-4847-b1c9-7ed4ea321f37.md) ['windows'] (sigma rule :x:)


### T1204.002
[Potentially Unwanted Applications (PUA)](tests/02f35d62-9fdc-4a97-b899-a5d9a876d295.md) ['windows'] (sigma rule :x:)

[Maldoc choice flags command execution](tests/0330a5d2-a45a-4272-a9ee-e364411c4b18.md) ['windows'] (sigma rule :x:)

[OSTap Payload Download](tests/3f3af983-118a-4fa1-85d3-ba4daa739d80.md) ['windows'] (sigma rule :x:)

[Excel 4 Macro](tests/4ea1fc97-8a46-4b4e-ba48-af43d2a98052.md) ['windows'] (sigma rule :x:)

[Office Generic Payload Download](tests/5202ee05-c420-4148-bf5e-fd7f7d24850c.md) ['windows'] (sigma rule :x:)

[OSTap Style Macro Execution](tests/8bebc690-18c7-4549-bc98-210f7019efff.md) ['windows'] (sigma rule :x:)

[Office launching .bat file from AppData](tests/9215ea92-1ded-41b7-9cd6-79f9a78397aa.md) ['windows'] (sigma rule :x:)

[Headless Chrome code execution via VBA](tests/a19ee671-ed98-4e9d-b19c-d1954a51585a.md) ['windows'] (sigma rule :x:)

[OSTAP JS version](tests/add560ef-20d6-4011-a937-2c340f930911.md) ['windows'] (sigma rule :x:)


### T1218.002
[Control Panel Items](tests/037e9d8a-9e46-4255-8b33-2ae3b545ca6f.md) ['windows'] (sigma rule :x:)


### T1016
[List Windows Firewall Rules](tests/038263cb-00f4-4b0a-98ae-0696c67e1752.md) ['windows'] (sigma rule :heavy_check_mark:)

[Qakbot Recon](tests/121de5c6-5818-4868-b8a7-8fd07c455c1b.md) ['windows'] (sigma rule :heavy_check_mark:)

[List Open Egress Ports](tests/4b467538-f102-491d-ace7-ed487b853bf5.md) ['windows'] (sigma rule :heavy_check_mark:)

[System Network Configuration Discovery on Windows](tests/970ab6a1-0157-4f3f-9a73-ec4166754b23.md) ['windows'] (sigma rule :heavy_check_mark:)

[Adfind - Enumerate Active Directory Subnet Objects](tests/9bb45dd7-c466-4f93-83a1-be30e56033ee.md) ['windows'] (sigma rule :heavy_check_mark:)

[System Network Configuration Discovery](tests/c141bbdb-7fca-4254-9fd6-f47e79447e17.md) ['macos', 'linux'] (sigma rule :x:)

[System Network Configuration Discovery (TrickBot Style)](tests/dafaf052-5508-402d-bf77-51e0700c02e2.md) ['windows'] (sigma rule :heavy_check_mark:)

[List macOS Firewall Rules](tests/ff1d8c25-2aa4-4f18-a425-fede4a41ee88.md) ['macos'] (sigma rule :x:)


### T1070.004
[Overwrite and delete a file with shred](tests/039b4b10-2900-404b-b67f-4b6d49aa6499.md) ['linux'] (sigma rule :x:)

[Delete Prefetch File](tests/36f96049-0ad7-4a5f-8418-460acaeb92fb.md) ['windows'] (sigma rule :x:)

[Delete a single file - Linux/macOS](tests/562d737f-2fc6-4b09-8c2a-7f8ff0828480.md) ['linux', 'macos'] (sigma rule :x:)

[Delete TeamViewer Log Files](tests/69f50a5f-967c-4327-a5bb-e1a9a9983785.md) ['windows'] (sigma rule :x:)

[Delete a single file - Windows cmd](tests/861ea0b4-708a-4d17-848d-186c9c7f17e3.md) ['windows'] (sigma rule :x:)

[Delete a single file - Windows PowerShell](tests/9dee89bd-9a98-4c4f-9e2d-4256690b0e72.md) ['windows'] (sigma rule :x:)

[Delete an entire folder - Linux/macOS](tests/a415f17e-ce8d-4ce2-a8b4-83b674e7017e.md) ['linux', 'macos'] (sigma rule :x:)

[Delete an entire folder - Windows cmd](tests/ded937c4-2add-42f7-9c2c-c742b7a98698.md) ['windows'] (sigma rule :x:)

[Delete an entire folder - Windows PowerShell](tests/edd779e4-a509-4cba-8dfa-a112543dbfb1.md) ['windows'] (sigma rule :x:)

[Delete Filesystem - Linux](tests/f3aa95fe-4f10-4485-ad26-abf22a764c52.md) ['linux'] (sigma rule :x:)


### T1543.004
[Launch Daemon](tests/03ab8df5-3a6b-4417-b6bd-bb7a5cfd74cf.md) ['macos'] (sigma rule :x:)


### T1222.002
[chmod - Change file or folder mode (symbolic mode) recursively](tests/0451125c-b5f6-488f-993b-5a32b09f7d8f.md) ['macos', 'linux'] (sigma rule :x:)

[chmod - Change file or folder mode (numeric mode)](tests/34ca1464-de9d-40c6-8c77-690adf36a135.md) ['macos', 'linux'] (sigma rule :x:)

[chown - Change file or folder ownership recursively](tests/3b015515-b3d8-44e9-b8cd-6fa84faf30b2.md) ['macos', 'linux'] (sigma rule :x:)

[chown - Change file or folder mode ownership only](tests/967ba79d-f184-4e0e-8d09-6362b3162e99.md) ['macos', 'linux'] (sigma rule :x:)

[chown - Change file or folder ownership and group recursively](tests/b78598be-ff39-448f-a463-adbf2a5b7848.md) ['macos', 'linux'] (sigma rule :x:)

[chown - Change file or folder ownership and group](tests/d169e71b-85f9-44ec-8343-27093ff3dfc0.md) ['macos', 'linux'] (sigma rule :x:)

[chattr - Remove immutable file attribute](tests/e7469fe2-ad41-4382-8965-99b94dd3c13f.md) ['macos', 'linux'] (sigma rule :x:)

[chmod - Change file or folder mode (numeric mode) recursively](tests/ea79f937-4a4d-4348-ace6-9916aec453a4.md) ['macos', 'linux'] (sigma rule :x:)

[chmod - Change file or folder mode (symbolic mode)](tests/fc9d6695-d022-4a80-91b1-381f5c35aff3.md) ['macos', 'linux'] (sigma rule :x:)


### T1070.005
[Remove Network Share PowerShell](tests/0512d214-9512-4d22-bde7-f37e058259b3.md) ['windows'] (sigma rule :x:)

[Remove Network Share](tests/09210ad5-1ef2-4077-9ad3-7351e13e9222.md) ['windows'] (sigma rule :x:)

[Add Network Share](tests/14c38f32-6509-46d8-ab43-d53e32d2b131.md) ['windows'] (sigma rule :x:)

[Remove Administrative Shares](tests/4299eff5-90f1-4446-b2f3-7f4f5cfd5d62.md) ['windows'] (sigma rule :x:)

[Disable Administrative Share Creation at Startup](tests/99c657aa-ebeb-4179-a665-69288fdd12b8.md) ['windows'] (sigma rule :x:)


### T1218.007
[Msiexec.exe - Execute Local MSI file](tests/0683e8f7-a27b-4b62-b7ab-dc7d4fed1df8.md) ['windows'] (sigma rule :x:)

[Msiexec.exe - Execute Arbitrary DLL](tests/66f64bd5-7c35-4c24-953a-04ca30a0a0ec.md) ['windows'] (sigma rule :x:)

[Msiexec.exe - Execute Remote MSI file](tests/bde7d2fe-d049-458d-a362-abda32a7e649.md) ['windows'] (sigma rule :x:)


### T1134.004
[Parent PID Spoofing using PowerShell](tests/069258f4-2162-46e9-9a25-c9c6c56150d2.md) ['windows'] (sigma rule :x:)

[Parent PID Spoofing - Spawn from Current Process](tests/14920ebd-1d61-491a-85e0-fe98efe37f25.md) ['windows'] (sigma rule :x:)

[Parent PID Spoofing - Spawn from New Process](tests/2988133e-561c-4e42-a15f-6281e6a9b2db.md) ['windows'] (sigma rule :x:)

[Parent PID Spoofing - Spawn from Specified Process](tests/cbbff285-9051-444a-9d17-c07cd2d230eb.md) ['windows'] (sigma rule :x:)

[Parent PID Spoofing - Spawn from svchost.exe](tests/e9f2b777-3123-430b-805d-5cedc66ab591.md) ['windows'] (sigma rule :x:)


### T1059.001
[Invoke-AppPathBypass](tests/06a220b6-7e29-4bd8-9d07-5b4d86742372.md) ['windows'] (sigma rule :x:)

[ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments](tests/0d181431-ddf3-4826-8055-2dbf63ae848b.md) ['windows'] (sigma rule :x:)

[PowerUp Invoke-AllChecks](tests/1289f78d-22d2-4590-ac76-166737e1811b.md) ['windows'] (sigma rule :x:)

[ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments](tests/1c0a870f-dc74-49cf-9afc-eccc45e58790.md) ['windows'] (sigma rule :x:)

[Powershell MsXml COM object - with prompt](tests/388a7340-dbc1-4c9d-8e59-b75ad8c6d5da.md) ['windows'] (sigma rule :x:)

[Obfuscation Tests](tests/4297c41a-8168-4138-972d-01f3ee92c804.md) ['windows'] (sigma rule :x:)

[Powershell XML requests](tests/4396927f-e503-427b-b023-31049b9b09a6.md) ['windows'] (sigma rule :x:)

[PowerShell Invoke Known Malicious Cmdlets](tests/49eb9404-5e0f-4031-a179-b40f7be385e3.md) ['windows'] (sigma rule :x:)

[ATHPowerShellCommandLineParameter -Command parameter variations](tests/686a9785-f99b-41d4-90df-66ed515f81d7.md) ['windows'] (sigma rule :x:)

[PowerShell Session Creation and Use](tests/7c1acec2-78fa-4305-a3e0-db2a54cddecd.md) ['windows'] (sigma rule :x:)

[ATHPowerShellCommandLineParameter -EncodedCommand parameter variations](tests/86a43bad-12e3-4e85-b97c-4d5cf25b95c3.md) ['windows'] (sigma rule :x:)

[Powershell invoke mshta.exe download](tests/8a2ad40b-12c7-4b25-8521-2737b0a415af.md) ['windows'] (sigma rule :x:)

[NTFS Alternate Data Stream Access](tests/8e5c5532-1181-4c1d-bb79-b3a9f5dbd680.md) ['windows'] (sigma rule :x:)

[PowerShell Downgrade Attack](tests/9148e7c4-9356-420e-a416-e896e9c0f73e.md) ['windows'] (sigma rule :x:)

[Run BloodHound from local disk](tests/a21bb23e-e677-4ee7-af90-6931b57b6350.md) ['windows'] (sigma rule :x:)

[PowerShell Command Execution](tests/a538de64-1c74-46ed-aa60-b995ed302598.md) ['windows'] (sigma rule :x:)

[Mimikatz - Cradlecraft PsSendKeys](tests/af1800cf-9f9d-4fd1-a709-14b1e6de020d.md) ['windows'] (sigma rule :x:)

[Run Bloodhound from Memory using Download Cradle](tests/bf8c1441-4674-4dab-8e4e-39d93d08f9b7.md) ['windows'] (sigma rule :x:)

[Powershell Invoke-DownloadCradle](tests/cc50fa2a-a4be-42af-a88f-e347ba0bf4d7.md) ['windows'] (sigma rule :x:)

[Mimikatz](tests/f3132740-55bc-48c4-bcc0-758a459cd027.md) ['windows'] (sigma rule :x:)

[PowerShell Fileless Script Execution](tests/fa050f5e-bc75-4230-af73-b6fd7852cd73.md) ['windows'] (sigma rule :x:)


### T1218.004
[InstallUtil Uninstall method call - '/installtype=notransaction /action=uninstall' variant](tests/06d9deba-f732-48a8-af8e-bdd6e4d98c1d.md) ['windows'] (sigma rule :x:)

[InstallUtil Uninstall method call - /U variant](tests/34428cfa-8e38-41e5-aff4-9e1f8f3a7b4b.md) ['windows'] (sigma rule :x:)

[InstallUtil evasive invocation](tests/559e6d06-bb42-4307-bff7-3b95a8254bad.md) ['windows'] (sigma rule :x:)

[InstallUtil HelpText method call](tests/5a683850-1145-4326-a0e5-e91ced3c6022.md) ['windows'] (sigma rule :x:)

[InstallUtil class constructor method call](tests/9b7a7cfc-dd2e-43f5-a885-c0a3c270dd93.md) ['windows'] (sigma rule :x:)

[InstallUtil Install method call](tests/9f9968a6-601a-46ca-b7b7-6d4fe0f98f0b.md) ['windows'] (sigma rule :x:)

[InstallHelper method call](tests/d43a5bde-ae28-4c55-a850-3f4c80573503.md) ['windows'] (sigma rule :x:)

[CheckIfInstallable method call](tests/ffd9c807-d402-47d2-879d-f915cf2a3a94.md) ['windows'] (sigma rule :x:)


### T1562.001
[Disable OpenDNS Umbrella](tests/07f43b33-1e15-4e99-be70-bc094157c849.md) ['macos'] (sigma rule :x:)

[Tamper with Windows Defender Evade Scanning -Folder](tests/0b19f4ee-de90-4059-88cb-63c800c683ed.md) ['windows'] (sigma rule :x:)

[AMSI Bypass - Remove AMSI Provider Reg Key](tests/13f09b91-c953-438e-845b-b585e51cac9b.md) ['windows'] (sigma rule :x:)

[Tamper with Windows Defender Registry](tests/1b3e0146-a1e5-4c5c-89fb-1bb2ffe8fc45.md) ['windows'] (sigma rule :x:)

[Disable macOS Gatekeeper](tests/2a821573-fb3f-4e71-92c3-daac7432f053.md) ['macos'] (sigma rule :x:)

[Tamper with Windows Defender Evade Scanning -Extension](tests/315f4be6-2240-4552-b3e1-d1047f5eecea.md) ['windows'] (sigma rule :x:)

[Remove Windows Defender Definition Files](tests/3d47daaa-2f56-43e0-94cc-caf5d8d52a68.md) ['windows'] (sigma rule :x:)

[Disable syslog](tests/4ce786f8-e601-44b5-bfae-9ebb15a7d1c8.md) ['linux'] (sigma rule :x:)

[Disable LittleSnitch](tests/62155dd8-bb3d-4f32-b31c-6532ff3ac6a3.md) ['macos'] (sigma rule :x:)

[AMSI Bypass - AMSI InitFailed](tests/695eed40-e949-40e5-b306-b4031e4154bd.md) ['windows'] (sigma rule :x:)

[Tamper with Windows Defender ATP PowerShell](tests/6b8df440-51ec-4d53-bf83-899591c9b5d7.md) ['windows'] (sigma rule :x:)

[Disable Microsoft Office Security Features](tests/6f5fb61b-4e56-4a3d-a8c3-82e13686c6d7.md) ['windows'] (sigma rule :x:)

[Unload Sysmon Filter Driver](tests/811b3e76-c41b-430c-ac0d-e2380bfaa164.md) ['windows'] (sigma rule :x:)

[Stop Crowdstrike Falcon on Linux](tests/828a1278-81cc-4802-96ab-188bf29ca77d.md) ['linux'] (sigma rule :x:)

[Disable Windows Defender with DISM](tests/871438ac-7d6e-432a-b27d-3e7db69faf58.md) ['windows'] (sigma rule :x:)

[Disable Carbon Black Response](tests/8fba7766-2d11-4b4a-979a-1e3d9cc9a88c.md) ['macos'] (sigma rule :x:)

[Disable Arbitrary Security Windows Service](tests/a1230893-56ac-4c81-b644-2108e982f8f5.md) ['windows'] (sigma rule :x:)

[Tamper with Windows Defender Evade Scanning -Process](tests/a123ce6a-3916-45d6-ba9c-7d4081315c27.md) ['windows'] (sigma rule :x:)

[Uninstall Sysmon](tests/a316fb2e-5344-470d-91c1-23e15c374edc.md) ['windows'] (sigma rule :x:)

[Tamper with Windows Defender Command Prompt](tests/aa875ed4-8935-47e2-b2c5-6ec00ab220d2.md) ['windows'] (sigma rule :x:)

[Stop and Remove Arbitrary Security Windows Service](tests/ae753dda-0f15-4af6-a168-b9ba16143143.md) ['windows'] (sigma rule :x:)

[Disable Cb Response](tests/ae8943f7-0f8d-44de-962d-fbc2e2f03eb8.md) ['linux'] (sigma rule :x:)

[Uninstall Crowdstrike Falcon on Windows](tests/b32b1ccf-f7c1-49bc-9ddd-7d7466a7b297.md) ['windows'] (sigma rule :x:)

[Stop and unload Crowdstrike Falcon on macOS](tests/b3e7510c-2d4c-4249-a33f-591a2bc83eef.md) ['macos'] (sigma rule :x:)

[office-365-Disable-AntiPhishRule](tests/b9bbae2c-2ba6-4cf3-b452-8e8f908696f3.md) ['office-365'] (sigma rule :x:)

[Disable SELinux](tests/fc225f36-9279-4c39-b3f9-5141ab74f8d8.md) ['linux'] (sigma rule :x:)


### T1201
[Examine password complexity policy - Ubuntu](tests/085fe567-ac84-47c7-ac4c-2688ce28265b.md) ['linux'] (sigma rule :x:)

[Examine local password policy - Windows](tests/4588d243-f24e-4549-b2e3-e627acc089f6.md) ['windows'] (sigma rule :heavy_check_mark:)

[Examine domain password policy - Windows](tests/46c2c362-2679-4ef5-aec9-0e958e135be4.md) ['windows'] (sigma rule :heavy_check_mark:)

[Examine password policy - macOS](tests/4b7fa042-9482-45e1-b348-4b756b2a0742.md) ['macos'] (sigma rule :x:)

[Examine password complexity policy - CentOS/RHEL 6.x](tests/6ce12552-0adb-4f56-89ff-95ce268f6358.md) ['linux'] (sigma rule :x:)

[Examine password complexity policy - CentOS/RHEL 7.x](tests/78a12e65-efff-4617-bc01-88f17d71315d.md) ['linux'] (sigma rule :x:)

[Examine password expiration policy - All Linux](tests/7c86c55c-70fa-4a05-83c9-3aa19b145d1a.md) ['linux'] (sigma rule :x:)


### T1486
[Encrypt files using ccrypt (Linux)](tests/08cbf59f-85da-4369-a5f4-049cffd7709f.md) ['linux'] (sigma rule :x:)

[Encrypt files using openssl (Linux)](tests/142752dc-ca71-443b-9359-cf6f497315f1.md) ['linux'] (sigma rule :x:)

[Encrypt files using 7z (Linux)](tests/53e6735a-4727-44cc-b35b-237682a151ad.md) ['linux'] (sigma rule :x:)

[PureLocker Ransom Note](tests/649349c7-9abf-493b-a7a2-b1aa4d141528.md) ['windows'] (sigma rule :heavy_check_mark:)

[Encrypt files using gpg (Linux)](tests/7b8ce084-3922-4618-8d22-95f996173765.md) ['linux'] (sigma rule :x:)


### T1218.010
[Regsvr32 local DLL execution](tests/08ffca73-9a3d-471a-aeb0-68b4aa3ab37b.md) ['windows'] (sigma rule :x:)

[Regsvr32 Registering Non DLL](tests/1ae5ea1f-0a4e-4e54-b2f5-4ac328a7f421.md) ['windows'] (sigma rule :x:)

[Regsvr32 local COM scriptlet execution](tests/449aa403-6aba-47ce-8a37-247d21ef0306.md) ['windows'] (sigma rule :x:)

[Regsvr32 Silent DLL Install Call DllRegisterServer](tests/9d71c492-ea2e-4c08-af16-c6994cdf029f.md) ['windows'] (sigma rule :x:)

[Regsvr32 remote COM scriptlet execution](tests/c9d0c4ef-8a96-4794-a75b-3d3a5e6f2a36.md) ['windows'] (sigma rule :x:)


### T1546.013
[Append malicious start-process cmdlet](tests/090e5aa5-32b6-473b-a49b-21e843a56896.md) ['windows'] (sigma rule :x:)


### T1049
[System Network Connections Discovery](tests/0940a971-809a-48f1-9c4d-b1d785e96ee5.md) ['windows'] (sigma rule :heavy_check_mark:)

[System Discovery using SharpView](tests/96f974bb-a0da-4d87-a744-ff33e73367e9.md) ['windows'] (sigma rule :heavy_check_mark:)

[System Network Connections Discovery Linux & MacOS](tests/9ae28d3f-190f-4fa0-b023-c7bd3e0eabf2.md) ['linux', 'macos'] (sigma rule :x:)

[System Network Connections Discovery with PowerShell](tests/f069f0f1-baad-4831-aa2b-eddac4baac4a.md) ['windows'] (sigma rule :x:)


### T1110.001
[Brute Force Credentials of single Active Directory domain users via SMB](tests/09480053-2f98-4854-be6e-71ae5f672224.md) ['windows'] (sigma rule :x:)

[Brute Force Credentials of single Azure AD user](tests/5a51ef57-299e-4d62-8e11-2d440df55e69.md) ['azure-ad'] (sigma rule :x:)

[Brute Force Credentials of single Active Directory domain user via LDAP against domain controller (NTLM or Kerberos)](tests/c2969434-672b-4ec8-8df0-bbb91f40e250.md) ['windows'] (sigma rule :x:)


### T1505.003
[Web Shell Written to Disk](tests/0a2ce662-1efa-496f-a472-2fe7b080db16.md) ['windows'] (sigma rule :x:)


### T1546.004
[Add command to .bashrc](tests/0a898315-4cfa-4007-bafe-33a4646d115f.md) ['macos', 'linux'] (sigma rule :x:)

[Add command to .bash_profile](tests/94500ae1-7e31-47e3-886b-c328da46872f.md) ['macos', 'linux'] (sigma rule :x:)


### T1090.001
[Connection Proxy](tests/0ac21132-4485-4212-a681-349e8a6637cd.md) ['macos', 'linux'] (sigma rule :x:)

[Connection Proxy for macOS UI](tests/648d68c1-8bcd-4486-9abe-71c6655b6a2c.md) ['macos'] (sigma rule :x:)

[portproxy reg key](tests/b8223ea9-4be2-44a6-b50a-9657a3d4e72a.md) ['windows'] (sigma rule :x:)


### T1069.002
[Elevated group enumeration using net group (Domain)](tests/0afb5163-8181-432e-9405-4322710c0c37.md) ['windows'] (sigma rule :heavy_check_mark:)

[Adfind - Query Active Directory Groups](tests/48ddc687-82af-40b7-8472-ff1e742e8274.md) ['windows'] (sigma rule :heavy_check_mark:)

[Find Local Admins via Group Policy (PowerView)](tests/64fdb43b-5259-467a-b000-1b02c00e510a.md) ['windows'] (sigma rule :heavy_check_mark:)

[Permission Groups Discovery PowerShell (Domain)](tests/6d5d8c96-3d2a-4da9-9d6d-9a9d341899a7.md) ['windows'] (sigma rule :heavy_check_mark:)

[Enumerate Users Not Requiring Pre Auth (ASRepRoast)](tests/870ba71e-6858-4f6d-895c-bb6237f6121b.md) ['windows'] (sigma rule :heavy_check_mark:)

[Find machines where user has local admin access (PowerView)](tests/a2d71eee-a353-4232-9f86-54f4288dd8c1.md) ['windows'] (sigma rule :heavy_check_mark:)

[Find local admins on all machines in domain (PowerView)](tests/a5f0d9f8-d3c9-46c0-8378-846ddd6b1cbd.md) ['windows'] (sigma rule :heavy_check_mark:)

[Basic Permission Groups Discovery Windows (Domain)](tests/dd66d77d-8998-48c0-8024-df263dc2ce5d.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1611
[Deploy container using nsenter container escape](tests/0b2f9520-a17a-4671-9dba-3bd034099fff.md) ['containers'] (sigma rule :x:)


### T1059.006
[Execute Python via Python executables (Linux)](tests/0b44d79b-570a-4b27-a31f-3bf2156e5eaa.md) ['linux'] (sigma rule :x:)

[Execute shell script via python's command mode arguement](tests/3a95cdb2-c6ea-4761-b24e-02b71889b8bb.md) ['linux'] (sigma rule :x:)

[Execute Python via scripts (Linux)](tests/6c4d1dcb-33c7-4c36-a8df-c6cfd0408be8.md) ['linux'] (sigma rule :x:)


### T1003.001
[Dump LSASS.exe Memory using ProcDump](tests/0be2230c-9ab3-4ac2-8826-3199b9a0ebf8.md) ['windows'] (sigma rule :x:)

[Windows Credential Editor](tests/0f7c5301-6859-45ba-8b4d-1fac30fc31ed.md) ['windows'] (sigma rule :heavy_check_mark:)

[Dump LSASS.exe Memory using comsvcs.dll](tests/2536dee2-12fb-459a-8c37-971844fa73be.md) ['windows'] (sigma rule :x:)

[Offline Credential Theft With Mimikatz](tests/453acf13-1dbd-47d7-b28a-172ce9228023.md) ['windows'] (sigma rule :x:)

[Dump LSASS.exe Memory using Out-Minidump.ps1](tests/6502c8f0-b775-4dbd-9193-1298f56b6781.md) ['windows'] (sigma rule :x:)

[Powershell Mimikatz](tests/66fb0bc1-3c3f-47e9-a298-550ecfefacbc.md) ['windows'] (sigma rule :heavy_check_mark:)

[Dump LSASS.exe Memory using direct system calls and API unhooking](tests/7ae7102c-a099-45c8-b985-4c7a2d05790d.md) ['windows'] (sigma rule :x:)

[Create Mini Dump of LSASS.exe using ProcDump](tests/7cede33f-0acd-44ef-9774-15511300b24b.md) ['windows'] (sigma rule :heavy_check_mark:)

[Dump LSASS.exe using imported Microsoft DLLs](tests/86fc3f40-237f-4701-b155-81c01c48d697.md) ['windows'] (sigma rule :x:)

[Dump LSASS with .Net 5 createdump.exe](tests/9d0072c8-7cca-45c4-bd14-f852cfa35cf0.md) ['windows'] (sigma rule :x:)

[LSASS read with pypykatz](tests/c37bc535-5c62-4195-9cc3-0517673171d8.md) ['windows'] (sigma rule :x:)

[Dump LSASS.exe Memory using NanoDump](tests/dddd4aca-bbed-46f0-984d-e4c5971c51ea.md) ['windows'] (sigma rule :x:)

[Dump LSASS.exe Memory using Windows Task Manager](tests/dea6c349-f1c6-44f3-87a1-1ed33a59a607.md) ['windows'] (sigma rule :x:)


### T1572
[DNS over HTTPS Regular Beaconing](tests/0c5f9705-c575-42a6-9609-cbbff4b2fc9b.md) ['windows'] (sigma rule :x:)

[DNS over HTTPS Long Domain Query](tests/748a73d5-cea4-4f34-84d8-839da5baa99c.md) ['windows'] (sigma rule :x:)

[DNS over HTTPS Large Query Volume](tests/ae9ef4b0-d8c1-49d4-8758-06206f19af0a.md) ['windows'] (sigma rule :x:)


### T1115
[Utilize Clipboard to store or execute commands from](tests/0cd14633-58d4-4422-9ede-daa2c9474ae7.md) ['windows'] (sigma rule :heavy_check_mark:)

[Execute commands from clipboard](tests/1ac2247f-65f8-4051-b51f-b0ccdfaaa5ff.md) ['macos'] (sigma rule :x:)

[Collect Clipboard Data via VBA](tests/9c8d5a72-9c98-48d3-b9bf-da2cc43bdf52.md) ['windows'] (sigma rule :heavy_check_mark:)

[Execute Commands from Clipboard using PowerShell](tests/d6dc21af-bec9-4152-be86-326b6babd416.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1083
[File and Directory Discovery (cmd.exe)](tests/0e36303b-6762-4500-b003-127743b80ba6.md) ['windows'] (sigma rule :heavy_check_mark:)

[Nix File and Directory Discovery 2](tests/13c5e1ae-605b-46c4-a79f-db28c77ff24e.md) ['macos', 'linux'] (sigma rule :x:)

[File and Directory Discovery (PowerShell)](tests/2158908e-b7ef-4c21-8a83-3ce4dd05a924.md) ['windows'] (sigma rule :heavy_check_mark:)

[Nix File and Diectory Discovery](tests/ffc8b249-372a-4b74-adcd-e4c0430842de.md) ['macos', 'linux'] (sigma rule :x:)


### T1552.001
[Extracting passwords with findstr](tests/0e56bf29-ff49-4ea5-9af4-3b81283fd513.md) ['windows'] (sigma rule :heavy_check_mark:)

[Access unattend.xml](tests/367d4004-5fc0-446d-823f-960c74ae52c3.md) ['windows'] (sigma rule :heavy_check_mark:)

[Extract Browser and System credentials with LaZagne](tests/9e507bb8-1d30-4e3b-a49b-cb5727d7ea79.md) ['macos'] (sigma rule :x:)

[Extract passwords with grep](tests/bd4cf0d1-7646-474e-8610-78ccf5a097c4.md) ['macos', 'linux'] (sigma rule :x:)

[Find and Access Github Credentials](tests/da4f751a-020b-40d7-b9ff-d433b7799803.md) ['macos', 'linux'] (sigma rule :x:)


### T1056.001
[Logging bash history to syslog](tests/0e59d59d-3265-4d35-bebd-bf5c1ec40db5.md) ['linux'] (sigma rule :x:)

[Bash session based keylogger](tests/7f85a946-a0ea-48aa-b6ac-8ff539278258.md) ['linux'] (sigma rule :x:)

[SSHD PAM keylogger](tests/81d7d2ad-d644-4b6a-bea7-28ffe43becca.md) ['linux'] (sigma rule :x:)

[Living off the land Terminal Input Capture on Linux with pam.d](tests/9c6bdb34-a89f-4b90-acb1-5970614c711b.md) ['linux'] (sigma rule :x:)

[Auditd keylogger](tests/a668edb9-334e-48eb-8c2e-5413a40867af.md) ['linux'] (sigma rule :x:)

[Input Capture](tests/d9b633ca-8efb-45e6-b838-70f595c6ae26.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1021.002
[Copy and Execute File with PsExec](tests/0eb03d41-79e4-4393-8e57-6344856be1cf.md) ['windows'] (sigma rule :x:)

[Map admin share](tests/3386975b-367a-4fbb-9d77-4dcf3639ffd3.md) ['windows'] (sigma rule :x:)

[Map Admin Share PowerShell](tests/514e9cd7-9207-4882-98b1-c8f791bae3c5.md) ['windows'] (sigma rule :x:)

[Execute command writing output to local Admin Share](tests/d41aaab5-bdfe-431d-a3d5-c29e9136ff46.md) ['windows'] (sigma rule :x:)


### T1087.001
[Show if a user account has ever logged in remotely](tests/0f0b6a29-08c3-44ad-a30b-47fd996b2110.md) ['linux'] (sigma rule :x:)

[Enumerate users and groups](tests/319e9f6c-7a9e-432e-8c62-9385c803b6f2.md) ['macos'] (sigma rule :x:)

[List opened files by user](tests/7e46c7a5-0142-45be-a858-1a3ecb4fd3cb.md) ['linux', 'macos'] (sigma rule :x:)

[Enumerate all accounts on Windows (Local)](tests/80887bec-5a9b-4efc-a81d-f83eb2eb32ab.md) ['windows'] (sigma rule :heavy_check_mark:)

[Enumerate logged on users via CMD (Local)](tests/a138085e-bfe5-46ba-a242-74a6fb884af3.md) ['windows'] (sigma rule :heavy_check_mark:)

[Enumerate all accounts via PowerShell (Local)](tests/ae4b6361-b5f8-46cb-a3f9-9cf108ccfe7b.md) ['windows'] (sigma rule :heavy_check_mark:)

[View accounts with UID 0](tests/c955a599-3653-4fe5-b631-f11c00eb0397.md) ['linux', 'macos'] (sigma rule :x:)

[Enumerate users and groups](tests/e6f36545-dc1e-47f0-9f48-7f730f54a02e.md) ['linux', 'macos'] (sigma rule :x:)

[Enumerate all accounts (Local)](tests/f8aab3dd-5990-4bf8-b8ab-2226c951696f.md) ['linux'] (sigma rule :x:)

[View sudoers access](tests/fed9be70-0186-4bde-9f8a-20945f9370c2.md) ['linux', 'macos'] (sigma rule :x:)


### T1113
[Screencapture](tests/0f47ceb1-720f-4275-96b8-21f0562217ac.md) ['macos'] (sigma rule :x:)

[Windows Screencapture](tests/3c898f62-626c-47d5-aad2-6de873d69153.md) ['windows'] (sigma rule :x:)

[X Windows Capture](tests/8206dd0c-faf6-4d74-ba13-7fbe13dce6ac.md) ['linux'] (sigma rule :x:)

[Capture Linux Desktop using Import Tool](tests/9cd1cccb-91e4-4550-9139-e20a586fcea1.md) ['linux'] (sigma rule :x:)

[Screencapture (silent)](tests/deb7d358-5fbd-4dc4-aecc-ee0054d2d9a4.md) ['macos'] (sigma rule :x:)

[Windows Screen Capture (CopyFromScreen)](tests/e9313014-985a-48ef-80d9-cde604ffc187.md) ['windows'] (sigma rule :x:)


### T1207
[DCShadow (Active Directory)](tests/0f4c5eb0-98a0-4496-9c3d-656b4f2bc8f6.md) ['windows'] (sigma rule :x:)


### T1218.001
[Compiled HTML Help Remote Payload](tests/0f8af516-9818-4172-922b-42986ef1e81d.md) ['windows'] (sigma rule :x:)

[Invoke CHM Shortcut Command with ITS and Help Topic](tests/15756147-7470-4a83-87fb-bb5662526247.md) ['windows'] (sigma rule :x:)

[Invoke CHM with default Shortcut Command Execution](tests/29d6f0d7-be63-4482-8827-ea77126c1ef7.md) ['windows'] (sigma rule :x:)

[Invoke CHM with Script Engine and Help Topic](tests/4f83adda-f5ec-406d-b318-9773c9ca92e5.md) ['windows'] (sigma rule :x:)

[Compiled HTML Help Local Payload](tests/5cb87818-0d7c-4469-b7ef-9224107aebe8.md) ['windows'] (sigma rule :x:)

[Invoke CHM Simulate Double click](tests/5decef42-92b8-4a93-9eb2-877ddcb9401a.md) ['windows'] (sigma rule :x:)

[Invoke CHM with InfoTech Storage Protocol Handler](tests/b4094750-5fc7-4e8e-af12-b4e36bf5e7f6.md) ['windows'] (sigma rule :x:)


### T1518
[Find and Display Safari Browser Version](tests/103d6533-fd2a-4d08-976a-4a598565280f.md) ['macos'] (sigma rule :x:)

[Find and Display Internet Explorer Browser Version](tests/68981660-6670-47ee-a5fa-7e74806420a4.md) ['windows'] (sigma rule :heavy_check_mark:)

[Applications Installed](tests/c49978f6-bd6e-4221-ad2c-9e3e30cc1e3b.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1074.001
[Stage data from Discovery.bat](tests/107706a5-6f9f-451a-adae-bab8c667829f.md) ['windows'] (sigma rule :x:)

[Stage data from Discovery.sh](tests/39ce0303-ae16-4b9e-bb5b-4f53e8262066.md) ['linux', 'macos'] (sigma rule :x:)

[Zip a Folder with PowerShell for Staging in Temp](tests/a57fbe4b-3440-452a-88a7-943531ac872a.md) ['windows'] (sigma rule :x:)


### T1546.001
[Change Default File Association](tests/10a08978-2045-4d62-8c42-1957bbbea102.md) ['windows'] (sigma rule :x:)


### T1566.001
[Download Phishing Attachment - VBScript](tests/114ccff9-ae6d-4547-9ead-4cd69f687306.md) ['windows'] (sigma rule :x:)

[Word spawned a command shell and used an IP address in the command line](tests/cbb6799a-425c-4f83-9194-5447a909d67f.md) ['windows'] (sigma rule :x:)


### T1132.001
[Base64 Encoded data.](tests/1164f70f-9a88-4dff-b9ff-dc70e7bf0c25.md) ['macos', 'linux'] (sigma rule :x:)

[XOR Encoded data.](tests/c3ed6d2a-e3ad-400d-ad78-bbfdbfeacc08.md) ['windows'] (sigma rule :x:)


### T1053.004
[Event Monitor Daemon Persistence](tests/11979f23-9b9d-482a-9935-6fc9cd022c3e.md) ['macos'] (sigma rule :x:)


### T1027.002
[Binary simply packed by UPX (linux)](tests/11c46cd8-e471-450e-acb8-52a1216ae6a4.md) ['linux'] (sigma rule :x:)

[Binary packed by UPX, with modified headers](tests/4d46e16b-5765-4046-9f25-a600d3e65e4d.md) ['macos'] (sigma rule :x:)

[Binary simply packed by UPX](tests/b16ef901-00bb-4dda-b4fc-a04db5067e20.md) ['macos'] (sigma rule :x:)

[Binary packed by UPX, with modified headers (linux)](tests/f06197f8-ff46-48c2-a0c6-afc1b50665e1.md) ['linux'] (sigma rule :x:)


### T1037.004
[rc.local](tests/126f71af-e1c9-405c-94ef-26a47b16c102.md) ['linux'] (sigma rule :x:)

[rc.common](tests/97a48daa-8bca-4bc0-b1a9-c1d163e762de.md) ['macos'] (sigma rule :x:)

[rc.common](tests/c33f3d80-5f04-419b-a13a-854d1cbdbf3a.md) ['linux'] (sigma rule :x:)


### T1059.003
[Writes text to a file and displays it.](tests/127b4afe-2346-4192-815c-69042bec570e.md) ['windows'] (sigma rule :x:)

[Create and Execute Batch Script](tests/9e8894c0-50bd-4525-a96c-d4ac78ece388.md) ['windows'] (sigma rule :x:)

[Suspicious Execution via Windows Command Shell](tests/d0eb3597-a1b3-4d65-b33b-2cda8d397f20.md) ['windows'] (sigma rule :x:)


### T1027
[DLP Evasion via Sensitive Data in VBA Macro over email](tests/129edb75-d7b8-42cd-a8ba-1f3db64ec4ad.md) ['windows'] (sigma rule :x:)

[Execute base64-encoded PowerShell from Windows Registry](tests/450e7218-7915-4be4-8b9b-464a49eafcec.md) ['windows'] (sigma rule :x:)

[Obfuscated Command in PowerShell](tests/8b3f4ed6-077b-4bdd-891c-2d237f19410f.md) ['windows'] (sigma rule :x:)

[Execute base64-encoded PowerShell](tests/a50d5a97-2531-499e-a1de-5544c74432c6.md) ['windows'] (sigma rule :x:)

[DLP Evasion via Sensitive Data in VBA Macro over HTTP](tests/e2d85e66-cb66-4ed7-93b1-833fc56c9319.md) ['windows'] (sigma rule :x:)

[Obfuscated Command Line using special Unicode characters](tests/e68b945c-52d0-4dd9-a5e8-d173d70c448f.md) ['windows'] (sigma rule :x:)

[Decode base64 Data into Script](tests/f45df6be-2e1e-4136-a384-8f18ab3826fb.md) ['macos', 'linux'] (sigma rule :x:)

[Execution from Compressed File](tests/f8c8a909-5f29-49ac-9244-413936ce6d1f.md) ['windows'] (sigma rule :x:)


### T1003.006
[DCSync (Active Directory)](tests/129efd28-8497-4c87-a1b0-73b9a870ca3e.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1112
[Modify Registry of Current User Profile - cmd](tests/1324796b-d0f6-455a-b4ae-21ffee6aa6b9.md) ['windows'] (sigma rule :x:)

[Javascript in registry](tests/15f44ea9-4571-4837-be9e-802431a7bfae.md) ['windows'] (sigma rule :x:)

[Modify Registry of Local Machine - cmd](tests/282f929a-6bc5-42b8-bd93-960c3ba35afe.md) ['windows'] (sigma rule :x:)

[Modify registry to store logon credentials](tests/c0413fb5-33e2-40b7-9b6f-60b29f4a7a18.md) ['windows'] (sigma rule :x:)

[Add domain to Trusted sites Zone](tests/cf447677-5a4e-4937-a82c-e47d254afd57.md) ['windows'] (sigma rule :x:)

[Change Powershell Execution Policy to Bypass](tests/f3a6cceb-06c9-48e5-8df8-8867a6814245.md) ['windows'] (sigma rule :x:)


### T1037.005
[Add file to Local Library StartupItems](tests/134627c3-75db-410e-bff8-7a920075f198.md) ['macos'] (sigma rule :x:)


### T1558.003
[Rubeus kerberoast](tests/14625569-6def-4497-99ac-8e7817105b55.md) ['windows'] (sigma rule :x:)

[Request for service tickets](tests/3f987809-3681-43c8-bcd8-b3ff3a28533a.md) ['windows'] (sigma rule :x:)

[Request All Tickets via PowerShell](tests/902f4ed2-1aba-4133-90f2-cff6d299d6da.md) ['windows'] (sigma rule :x:)

[Request A Single Ticket via PowerShell](tests/988539bc-2ed7-4e62-aec6-7c5cf6680863.md) ['windows'] (sigma rule :x:)

[Extract all accounts in use as SPN using setspn](tests/e6f4affd-d826-4871-9a62-6c9004b8fe06.md) ['windows'] (sigma rule :x:)


### T1221
[WINWORD Remote Template Injection](tests/1489e08a-82c7-44ee-b769-51b72d03521d.md) ['windows'] (sigma rule :x:)


### T1548.003
[Sudo usage](tests/150c3a08-ee6e-48a6-aeaf-3659d24ceb4e.md) ['macos', 'linux'] (sigma rule :x:)

[Disable tty_tickets for sudo caching](tests/91a60b03-fb75-4d24-a42e-2eb8956e8de1.md) ['macos', 'linux'] (sigma rule :x:)

[Unlimited sudo cache timeout](tests/a7b17659-dd5e-46f7-b7d1-e6792c91d0bc.md) ['macos', 'linux'] (sigma rule :x:)


### T1518.001
[Security Software Discovery - AV Discovery via WMI](tests/1553252f-14ea-4d3b-8a08-d7a4211aa945.md) ['windows'] (sigma rule :heavy_check_mark:)

[Security Software Discovery - ps (Linux)](tests/23b91cd2-c99c-4002-9e41-317c63e024a2.md) ['linux'] (sigma rule :x:)

[Security Software Discovery - powershell](tests/7f566051-f033-49fb-89de-b6bacab730f0.md) ['windows'] (sigma rule :heavy_check_mark:)

[Security Software Discovery - ps (macOS)](tests/ba62ce11-e820-485f-9c17-6f3c857cd840.md) ['macos'] (sigma rule :x:)

[Security Software Discovery](tests/f92a380f-ced9-491f-b338-95a991418ce2.md) ['windows'] (sigma rule :heavy_check_mark:)

[Security Software Discovery - Sysmon Service](tests/fe613cf3-8009-4446-9a0f-bc78a15b66c9.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1562.004
[Opening ports for proxy - HARDRAIN](tests/15e57006-79dd-46df-9bf9-31bc24fb5a80.md) ['windows'] (sigma rule :x:)

[Tail the UFW firewall log file](tests/419cca0c-fa52-4572-b0d7-bc7c6f388a27.md) ['linux'] (sigma rule :x:)

[Allow Executable Through Firewall Located in Non-Standard Location](tests/6f5822d2-d38d-4f48-9bfc-916607ff6b8c.md) ['windows'] (sigma rule :x:)

[Edit UFW firewall main configuration file](tests/7b697ece-8270-46b5-bbc7-6b9e27081831.md) ['linux'] (sigma rule :x:)

[Disable Microsoft Defender Firewall](tests/88d05800-a5e4-407e-9b53-ece4174f197f.md) ['windows'] (sigma rule :x:)

[Turn off UFW logging](tests/8a95b832-2c2a-494d-9cb0-dc9dd97c8bad.md) ['linux'] (sigma rule :x:)

[Open a local port through Windows Firewall to any profile](tests/9636dd6e-7599-40d2-8eee-ac16434f35ed.md) ['windows'] (sigma rule :x:)

[Stop/Start UFW firewall systemctl](tests/9fd99609-1854-4f3c-b47b-97d9a5972bd1.md) ['linux'] (sigma rule :x:)

[Disable Microsoft Defender Firewall via Registry](tests/afedc8c4-038c-4d82-b3e5-623a95f8a612.md) ['windows'] (sigma rule :x:)

[Add and delete UFW firewall rules](tests/b2563a4e-c4b8-429c-8d47-d5bcb227ba7a.md) ['linux'] (sigma rule :x:)

[Edit UFW firewall user.rules file](tests/beaf815a-c883-4194-97e9-fdbbb2bbdd7c.md) ['linux'] (sigma rule :x:)

[Edit UFW firewall ufw.conf file](tests/c1d8c4eb-88da-4927-ae97-c7c25893803b.md) ['linux'] (sigma rule :x:)

[Edit UFW firewall sysctl.conf file](tests/c4ae0701-88d3-4cd8-8bce-4801ed9f97e4.md) ['linux'] (sigma rule :x:)

[Allow SMB and RDP on Microsoft Defender Firewall](tests/d9841bf8-f161-4c73-81e9-fd773a5ff8c1.md) ['windows'] (sigma rule :x:)

[Stop/Start UFW firewall](tests/fe135572-edcd-49a2-afe6-1d39521c5a9a.md) ['linux'] (sigma rule :x:)


### T1482
[Adfind - Enumerate Active Directory Trusts](tests/15fe436d-e771-4ff3-b655-2dca9ba52834.md) ['windows'] (sigma rule :heavy_check_mark:)

[Windows - Discover domain trusts with nltest](tests/2e22641d-0498-48d2-b9ff-c71e496ccdbe.md) ['windows'] (sigma rule :heavy_check_mark:)

[Windows - Discover domain trusts with dsquery](tests/4700a710-c821-4e17-a3ec-9e4c81d6845f.md) ['windows'] (sigma rule :heavy_check_mark:)

[Get-ForestTrust with PowerView](tests/58ed10e8-0738-4651-8408-3a3e9a526279.md) ['windows'] (sigma rule :heavy_check_mark:)

[Powershell enumerate domains and forests](tests/c58fbc62-8a62-489e-8f2d-3565d7d96f30.md) ['windows'] (sigma rule :heavy_check_mark:)

[Adfind - Enumerate Active Directory OUs](tests/d1c73b96-ab87-4031-bad8-0e1b3b8bf3ec.md) ['windows'] (sigma rule :heavy_check_mark:)

[Get-DomainTrust with PowerView](tests/f974894c-5991-4b19-aaf5-7cc2fe298c5d.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1070.002
[Overwrite Linux Mail Spool](tests/1602ff76-ed7f-4c94-b550-2f727b4782d4.md) ['linux'] (sigma rule :x:)

[rm -rf](tests/989cc1b1-3642-4260-a809-54f9dd559683.md) ['macos', 'linux'] (sigma rule :x:)

[Overwrite Linux Log](tests/d304b2dc-90b4-4465-a650-16ddd503f7b5.md) ['linux'] (sigma rule :x:)


### T1087.002
[Enumerate logged on users via CMD (Domain)](tests/161dcd85-d014-4f5e-900c-d3eaae82a0f7.md) ['windows'] (sigma rule :heavy_check_mark:)

[Enumerate Active Directory for Unconstrained Delegation](tests/46f8dbe9-22a5-4770-8513-66119c5be63b.md) ['windows'] (sigma rule :heavy_check_mark:)

[Adfind - Enumerate Active Directory Exchange AD Objects](tests/5e2938fb-f919-47b6-8b29-2f6a1f718e99.md) ['windows'] (sigma rule :heavy_check_mark:)

[Enumerate all accounts (Domain)](tests/6fbc9e68-5ad7-444a-bd11-8bf3136c477e.md) ['windows'] (sigma rule :heavy_check_mark:)

[Adfind -Listing password policy](tests/736b4f53-f400-4c22-855d-1a6b5a551600.md) ['windows'] (sigma rule :heavy_check_mark:)

[Enumerate all accounts via PowerShell (Domain)](tests/8b8a6449-be98-4f42-afd2-dedddc7453b2.md) ['windows'] (sigma rule :heavy_check_mark:)

[Automated AD Recon (ADRecon)](tests/95018438-454a-468c-a0fa-59c800149b59.md) ['windows'] (sigma rule :heavy_check_mark:)

[Adfind - Enumerate Active Directory Admins](tests/b95fd967-4e62-4109-b48d-265edfd28c3a.md) ['windows'] (sigma rule :heavy_check_mark:)

[Enumerate Default Domain Admin Details (Domain)](tests/c70ab9fd-19e2-4e02-a83c-9cfa8eaa8fef.md) ['windows'] (sigma rule :heavy_check_mark:)

[Adfind - Enumerate Active Directory User Objects](tests/e1ec8d20-509a-4b9a-b820-06c9b2da8eb7.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1059.005
[Visual Basic script execution to gather local computer information](tests/1620de42-160a-4fe5-bbaf-d3fef0181ce9.md) ['windows'] (sigma rule :x:)

[Extract Memory via VBA](tests/8faff437-a114-4547-9a60-749652a03df6.md) ['windows'] (sigma rule :x:)

[Encoded VBS code execution](tests/e8209d5f-e42d-45e6-9c2f-633ac4f1eefa.md) ['windows'] (sigma rule :x:)


### T1071.004
[DNS Large Query Volume](tests/1700f5d6-5a44-487b-84de-bc66f507b0a6.md) ['windows'] (sigma rule :x:)

[DNS Regular Beaconing](tests/3efc144e-1af8-46bb-8ca2-1376bb6db8b6.md) ['windows'] (sigma rule :x:)

[DNS C2](tests/e7bf9802-2e78-4db9-93b5-181b7bcd37d7.md) ['windows'] (sigma rule :x:)

[DNS Long Domain Query](tests/fef31710-223a-40ee-8462-a396d6b66978.md) ['windows'] (sigma rule :x:)


### T1555.001
[Keychain](tests/1864fdec-ff86-4452-8c30-f12507582a93.md) ['macos'] (sigma rule :x:)


### T1548.001
[Provide the SetUID capability to a file](tests/1ac3272f-9bcf-443a-9888-4b1d3de785c1.md) ['linux'] (sigma rule :x:)

[Set a SetUID flag on file](tests/759055b3-3885-4582-a8ec-c00c9d64dd79.md) ['macos', 'linux'] (sigma rule :x:)

[Make and modify binary from C source](tests/896dfe97-ae43-4101-8e96-9a7996555d80.md) ['macos', 'linux'] (sigma rule :x:)

[Make and modify capabilities of a binary](tests/db53959c-207d-4000-9e7a-cd8eb417e072.md) ['linux'] (sigma rule :x:)

[Set a SetGID flag on file](tests/db55f666-7cba-46c6-9fe6-205a05c3242c.md) ['macos', 'linux'] (sigma rule :x:)


### T1135
[Network Share Discovery PowerShell](tests/1b0814d1-bb24-402d-9615-1b20c50733fb.md) ['windows'] (sigma rule :heavy_check_mark:)

[Network Share Discovery command prompt](tests/20f1097d-81c1-405c-8380-32174d493bbb.md) ['windows'] (sigma rule :heavy_check_mark:)

[Network Share Discovery - linux](tests/875805bc-9e86-4e87-be86-3a5527315cae.md) ['linux'] (sigma rule :x:)

[View available share drives](tests/ab39a04f-0c93-4540-9ff2-83f862c385ae.md) ['windows'] (sigma rule :heavy_check_mark:)

[Share Discovery with PowerView](tests/b1636f0a-ba82-435c-b699-0d78794d8bfd.md) ['windows'] (sigma rule :heavy_check_mark:)

[PowerView ShareFinder](tests/d07e4cc1-98ae-447e-9d31-36cb430d28c4.md) ['windows'] (sigma rule :heavy_check_mark:)

[Network Share Discovery](tests/f94b5ad9-911c-4eff-9718-fd21899db4f7.md) ['macos'] (sigma rule :x:)


### T1220
[WMIC bypass using local XSL file](tests/1b237334-3e21-4a0c-8178-b8c996124988.md) ['windows'] (sigma rule :x:)

[WMIC bypass using remote XSL file](tests/7f5be499-33be-4129-a560-66021f379b9b.md) ['windows'] (sigma rule :x:)

[MSXSL Bypass using remote files](tests/a7c3ab07-52fb-49c8-ab6d-e9c6d4a0a985.md) ['windows'] (sigma rule :x:)

[MSXSL Bypass using local files](tests/ca23bfb2-023f-49c5-8802-e66997de462d.md) ['windows'] (sigma rule :x:)


### T1070.001
[Clear Event Logs via VBA](tests/1b682d84-f075-4f93-9a89-8a8de19ffd6e.md) ['windows'] (sigma rule :x:)

[Delete System Logs Using Clear-EventLog](tests/b13e9306-3351-4b4b-a6e8-477358b0b498.md) ['windows'] (sigma rule :x:)

[Clear Logs](tests/e6abb60e-26b8-41da-8aae-0c35174b0967.md) ['windows'] (sigma rule :x:)


### T1219
[GoToAssist Files Detected Test on Windows](tests/1b72b3bd-72f8-4b63-a30b-84e91b9c3578.md) ['windows'] (sigma rule :x:)

[ScreenConnect Application Download and Install on Windows](tests/4a18cc4e-416f-4966-9a9d-75731c4684c0.md) ['windows'] (sigma rule :x:)

[AnyDesk Files Detected Test on Windows](tests/6b8b7391-5c0a-4f8c-baee-78d8ce0ce330.md) ['windows'] (sigma rule :x:)

[TeamViewer Files Detected Test on Windows](tests/8ca3b96d-8983-4a7f-b125-fc98cc0a2aa0.md) ['windows'] (sigma rule :x:)

[LogMeIn Files Detected Test on Windows](tests/d03683ec-aae0-42f9-9b4c-534780e0f8e1.md) ['windows'] (sigma rule :x:)


### T1531
[Change User Password - Windows](tests/1b99ef28-f83c-4ec5-8a08-1a56263a5bb2.md) ['windows'] (sigma rule :heavy_check_mark:)

[Remove Account From Domain Admin Group](tests/43f71395-6c37-498e-ab17-897d814a0947.md) ['windows'] (sigma rule :heavy_check_mark:)

[Delete User - Windows](tests/f21a1d7d-a62f-442a-8c3a-2440d43b19e5.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1490
[Windows - Disable the SR scheduled task](tests/1c68c68d-83a4-4981-974e-8993055fa034.md) ['windows'] (sigma rule :heavy_check_mark:)

[Windows - wbadmin Delete Windows Backup Catalog](tests/263ba6cb-ea2b-41c9-9d4e-b652dadd002c.md) ['windows'] (sigma rule :heavy_check_mark:)

[Windows - Delete Volume Shadow Copies via WMI with PowerShell](tests/39a295ca-7059-4a88-86f6-09556c1211e7.md) ['windows'] (sigma rule :x:)

[Windows - Delete Volume Shadow Copies](tests/43819286-91a9-4369-90ed-d31fb4da2c01.md) ['windows'] (sigma rule :heavy_check_mark:)

[Windows - wbadmin Delete systemstatebackup](tests/584331dd-75bc-4c02-9e0b-17f5fd81c748.md) ['windows'] (sigma rule :heavy_check_mark:)

[Windows - Delete Volume Shadow Copies via WMI](tests/6a3ff8dd-f49c-4272-a658-11c2fe58bd88.md) ['windows'] (sigma rule :heavy_check_mark:)

[Windows - Delete Backup Files](tests/6b1dbaf6-cc8a-4ea6-891f-6058569653bf.md) ['windows'] (sigma rule :x:)

[Windows - Disable Windows Recovery Console Repair](tests/cf21060a-80b3-4238-a595-22525de4ab81.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1055
[Shellcode execution via VBA](tests/1c91e740-1729-4329-b779-feba6e71d048.md) ['windows'] (sigma rule :x:)

[Remote Process Injection in LSASS via mimikatz](tests/3203ad24-168e-4bec-be36-f79b13ef8a83.md) ['windows'] (sigma rule :x:)


### T1217
[List Mozilla Firefox Bookmark Database Files on macOS](tests/1ca1f9c7-44bc-46bb-8c85-c50e2e94267b.md) ['macos'] (sigma rule :x:)

[List Mozilla Firefox Bookmark Database Files on Linux](tests/3a41f169-a5ab-407f-9269-abafdb5da6c2.md) ['linux'] (sigma rule :x:)

[List Mozilla Firefox bookmarks on Windows with command prompt](tests/4312cdbc-79fc-4a9c-becc-53d49c734bc5.md) ['windows'] (sigma rule :heavy_check_mark:)

[List Internet Explorer Bookmarks using the command prompt](tests/727dbcdb-e495-4ab1-a6c4-80c7f77aef85.md) ['windows'] (sigma rule :heavy_check_mark:)

[List Google Chrome / Edge Chromium Bookmarks on Windows with command prompt](tests/76f71e2f-480e-4bed-b61e-398fe17499d5.md) ['windows'] (sigma rule :heavy_check_mark:)

[List Google Chrome Bookmark JSON Files on macOS](tests/b789d341-154b-4a42-a071-9111588be9bc.md) ['macos'] (sigma rule :x:)

[List Google Chrome Bookmarks on Windows with powershell](tests/faab755e-4299-48ec-8202-fc7885eb6545.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1048.003
[Exfiltration Over Alternative Protocol - HTTP](tests/1d1abbd6-a3d3-4b2e-bef5-c59293f46eff.md) ['macos', 'linux'] (sigma rule :x:)

[Exfiltration Over Alternative Protocol - HTTP](tests/6aa58451-1121-4490-a8e9-1dada3f1c68c.md) ['windows'] (sigma rule :x:)

[Exfiltration Over Alternative Protocol - DNS](tests/c403b5a4-b5fc-49f2-b181-d1c80d27db45.md) ['linux'] (sigma rule :x:)

[Exfiltration Over Alternative Protocol - ICMP](tests/dd4b4421-2e25-4593-90ae-7021947ad12e.md) ['windows'] (sigma rule :x:)

[Exfiltration Over Alternative Protocol - SMTP](tests/ec3a835e-adca-4c7c-88d2-853b69c11bb9.md) ['windows'] (sigma rule :x:)


### T1124
[System Time Discovery - PowerShell](tests/1d5711d6-655c-4a47-ae9c-6503c74fa877.md) ['windows'] (sigma rule :x:)

[System Time Discovery](tests/20aba24b-e61f-4b26-b4ce-4784f763ca20.md) ['windows'] (sigma rule :x:)

[System Time Discovery in macOS](tests/f449c933-0891-407f-821e-7916a21a1a6f.md) ['macos'] (sigma rule :x:)


### T1069.001
[Basic Permission Groups Discovery Windows (Local)](tests/1f454dd6-e134-44df-bebb-67de70fb6cd8.md) ['windows'] (sigma rule :heavy_check_mark:)

[WMIObject Group Discovery](tests/69119e58-96db-4110-ad27-954e48f3bb13.md) ['windows'] (sigma rule :heavy_check_mark:)

[Wmic Group Discovery](tests/7413be50-be8e-430f-ad4d-07bf197884b2.md) ['windows'] (sigma rule :heavy_check_mark:)

[Permission Groups Discovery (Local)](tests/952931a4-af0b-4335-bbbe-73c8c5b327ae.md) ['macos', 'linux'] (sigma rule :x:)

[Permission Groups Discovery PowerShell (Local)](tests/a580462d-2c19-4bc7-8b9a-57a41b7d3ba4.md) ['windows'] (sigma rule :heavy_check_mark:)

[SharpHound3 - LocalAdmin](tests/e03ada14-0980-4107-aff1-7783b2b59bb1.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1070.006
[Set a file's modification timestamp](tests/20ef1523-8758-4898-b5a2-d026cc3d2c52.md) ['linux', 'macos'] (sigma rule :x:)

[Set a file's access timestamp](tests/5f9113d5-ed75-47ed-ba23-ea3573d05810.md) ['linux', 'macos'] (sigma rule :x:)

[Modify file timestamps using reference file](tests/631ea661-d661-44b0-abdb-7a7f3fc08e50.md) ['linux', 'macos'] (sigma rule :x:)

[Set a file's creation timestamp](tests/8164a4a6-f99c-4661-ac4f-80f5e4e78d2b.md) ['linux', 'macos'] (sigma rule :x:)

[Windows - Modify file creation timestamp with PowerShell](tests/b3b2c408-2ff0-4a33-b89b-1cb46a9e6a9c.md) ['windows'] (sigma rule :x:)

[Windows - Timestomp a File](tests/d7512c33-3a75-4806-9893-69abc3ccdd43.md) ['windows'] (sigma rule :x:)

[Windows - Modify file last access timestamp with PowerShell](tests/da627f63-b9bd-4431-b6f8-c5b44d061a62.md) ['windows'] (sigma rule :x:)

[Windows - Modify file last modified timestamp with PowerShell](tests/f8f6634d-93e1-4238-8510-f8a90a20dcf2.md) ['windows'] (sigma rule :x:)


### T1562.006
[Auditing Configuration Changes on Linux Host](tests/212cfbcf-4770-4980-bc21-303e37abd0e3.md) ['linux'] (sigma rule :x:)

[Logging Configuration Changes on Linux Host](tests/7d40bc58-94c7-4fbb-88d9-ebce9fcdb60c.md) ['linux'] (sigma rule :x:)


### T1003.003
[Create Symlink to Volume Shadow Copy](tests/21748c28-2793-4284-9e07-d6d028b66702.md) ['windows'] (sigma rule :x:)

[Create Volume Shadow Copy with WMI](tests/224f7de0-8f0a-4a94-b5d8-989b036c86da.md) ['windows'] (sigma rule :x:)

[Dump Active Directory Database with NTDSUtil](tests/2364e33d-ceab-4641-8468-bfb1d7cc2723.md) ['windows'] (sigma rule :x:)

[Create Volume Shadow Copy with Powershell](tests/542bb97e-da53-436b-8e43-e0a7d31a6c24.md) ['windows'] (sigma rule :x:)

[Copy NTDS.dit from Volume Shadow Copy](tests/c6237146-9ea6-4711-85c9-c56d263a6b03.md) ['windows'] (sigma rule :x:)

[Create Volume Shadow Copy remotely with WMI](tests/d893459f-71f0-484d-9808-ec83b2b64226.md) ['windows'] (sigma rule :x:)

[Create Volume Shadow Copy with vssadmin](tests/dcebead7-6c28-4b4b-bf3c-79deb1b1fc7f.md) ['windows'] (sigma rule :x:)


### T1573
[OpenSSL C2](tests/21caf58e-87ad-440c-a6b8-3ac259964003.md) ['windows'] (sigma rule :x:)


### T1489
[Windows - Stop service using Service Controller](tests/21dfb440-830d-4c86-a3e5-2a491d5a8d04.md) ['windows'] (sigma rule :heavy_check_mark:)

[Windows - Stop service using net.exe](tests/41274289-ec9c-4213-bea4-e43c4aa57954.md) ['windows'] (sigma rule :heavy_check_mark:)

[Windows - Stop service by killing process](tests/f3191b84-c38b-400b-867e-3a217a27795f.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1571
[Testing usage of uncommonly used port with PowerShell](tests/21fe622f-8e53-4b31-ba83-6d333c2583f4.md) ['windows'] (sigma rule :x:)

[Testing usage of uncommonly used port](tests/5db21e1d-dd9c-4a50-b885-b1e748912767.md) ['linux', 'macos'] (sigma rule :x:)


### T1082
[Windows MachineGUID Discovery](tests/224b4daf-db44-404e-b6b2-f4d1f0126ef8.md) ['windows'] (sigma rule :x:)

[Linux VM Check via Hardware](tests/31dad7ad-2286-4c02-ae92-274418c85fec.md) ['linux'] (sigma rule :x:)

[Hostname Discovery](tests/486e88ea-4f56-470f-9b57-3f4d73f39133.md) ['linux', 'macos'] (sigma rule :x:)

[System Information Discovery](tests/66703791-c902-4560-8770-42b8a91f7667.md) ['windows'] (sigma rule :x:)

[Griffon Recon](tests/69bd4abe-8759-49a6-8d21-0f15822d6370.md) ['windows'] (sigma rule :x:)

[Linux VM Check via Kernel Modules](tests/8057d484-0fae-49a4-8302-4812c4f1e64e.md) ['linux'] (sigma rule :x:)

[Hostname Discovery (Windows)](tests/85cfbf23-4a1e-4342-8792-007e004b975f.md) ['windows'] (sigma rule :x:)

[List OS Information](tests/cccb070c-df86-4216-a5bc-9fb60c74e27c.md) ['linux', 'macos'] (sigma rule :x:)

[System Information Discovery](tests/edff98ec-0f73-4f63-9890-6b117092aff6.md) ['macos'] (sigma rule :x:)

[Environment variables discovery on windows](tests/f400d1c0-1804-4ff8-b069-ef5ddd2adbf3.md) ['windows'] (sigma rule :x:)

[Environment variables discovery on macos and linux](tests/fcbdd43f-f4ad-42d5-98f3-0218097e2720.md) ['macos', 'linux'] (sigma rule :x:)


### T1218.011
[Execution of HTA and VBS Files using Rundll32 and URL.dll](tests/22cfde89-befe-4e15-9753-47306b37a6e3.md) ['windows'] (sigma rule :x:)

[Rundll32 syssetup.dll Execution](tests/41fa324a-3946-401e-bbdd-d7991c628125.md) ['windows'] (sigma rule :x:)

[Rundll32 ieadvpack.dll Execution](tests/5e46a58e-cbf6-45ef-a289-ed7754603df9.md) ['windows'] (sigma rule :x:)

[Rundll32 execute VBscript command](tests/638730e7-7aed-43dc-bf8c-8117f805f5bb.md) ['windows'] (sigma rule :x:)

[Rundll32 setupapi.dll Execution](tests/71d771cd-d6b3-4f34-bc76-a63d47a10b19.md) ['windows'] (sigma rule :x:)

[Launches an executable using Rundll32 and pcwutl.dll](tests/9f5d081a-ee5a-42f9-a04e-b7bdc487e676.md) ['windows'] (sigma rule :x:)

[Rundll32 execute JavaScript Remote Payload With GetObject](tests/cf3bdb9a-dd11-4b6c-b0d0-9e22b68a71be.md) ['windows'] (sigma rule :x:)

[Rundll32 advpack.dll Execution](tests/d91cae26-7fc1-457b-a854-34c8aad48c89.md) ['windows'] (sigma rule :x:)


### T1555
[Extract Windows Credential Manager via VBA](tests/234f9b7c-b53d-4f32-897b-b880a6c9ea7b.md) ['windows'] (sigma rule :heavy_check_mark:)

[Enumerate credentials from Windows Credential Manager using vaultcmd.exe [Windows Credentials]](tests/36753ded-e5c4-4eb5-bc3c-e8fba236878d.md) ['windows'] (sigma rule :heavy_check_mark:)

[Dump credentials from Windows Credential Manager With PowerShell [web Credentials]](tests/8fd5a296-6772-4766-9991-ff4e92af7240.md) ['windows'] (sigma rule :heavy_check_mark:)

[Enumerate credentials from Windows Credential Manager using vaultcmd.exe [Web Credentials]](tests/bc071188-459f-44d5-901a-f8f2625b2d2e.md) ['windows'] (sigma rule :heavy_check_mark:)

[Dump credentials from Windows Credential Manager With PowerShell [windows Credentials]](tests/c89becbe-1758-4e7d-a0f4-97d2188a23e3.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1548.002
[UACME Bypass Method 56](tests/235ec031-cd2d-465d-a7ae-68bab281e80e.md) ['windows'] (sigma rule :x:)

[Bypass UAC using SilentCleanup task](tests/28104f8a-4ff1-4582-bcf6-699dce156608.md) ['windows'] (sigma rule :x:)

[Bypass UAC using sdclt DelegateExecute](tests/3be891eb-4608-4173-87e8-78b494c029b7.md) ['windows'] (sigma rule :x:)

[Bypass UAC using ComputerDefaults (PowerShell)](tests/3c51abf2-44bf-42d8-9111-dc96ff66750f.md) ['windows'] (sigma rule :x:)

[Bypass UAC using Fodhelper - PowerShell](tests/3f627297-6c38-4e7d-a278-fc2563eaaeaa.md) ['windows'] (sigma rule :x:)

[Bypass UAC using Event Viewer (cmd)](tests/5073adf8-9a50-4bd9-b298-a9bd2ead8af9.md) ['windows'] (sigma rule :x:)

[UACME Bypass Method 39](tests/56163687-081f-47da-bb9c-7b231c5585cf.md) ['windows'] (sigma rule :x:)

[Bypass UAC using Fodhelper](tests/58f641ea-12e3-499a-b684-44dee46bd182.md) ['windows'] (sigma rule :x:)

[UACME Bypass Method 34](tests/695b2dac-423e-448e-b6ef-5b88e93011d6.md) ['windows'] (sigma rule :x:)

[UACME Bypass Method 61](tests/7825b576-744c-4555-856d-caf3460dc236.md) ['windows'] (sigma rule :x:)

[UACME Bypass Method 23](tests/8ceab7a2-563a-47d2-b5ba-0995211128d7.md) ['windows'] (sigma rule :x:)

[Disable UAC using reg.exe](tests/9e8af564-53ec-407e-aaa8-3cb20c3af7f9.md) ['windows'] (sigma rule :x:)

[Bypass UAC using Event Viewer (PowerShell)](tests/a6ce9acf-842a-4af6-8f79-539be7608e2b.md) ['windows'] (sigma rule :x:)

[UACME Bypass Method 31](tests/b0f76240-9f33-4d34-90e8-3a7d501beb15.md) ['windows'] (sigma rule :x:)

[UACME Bypass Method 59](tests/dfb1b667-4bb8-4a63-a85e-29936ea75f29.md) ['windows'] (sigma rule :x:)

[UACME Bypass Method 33](tests/e514bb03-f71c-4b22-9092-9f961ec6fb03.md) ['windows'] (sigma rule :x:)

[Bypass UAC by Mocking Trusted Directories](tests/f7a35090-6f7f-4f64-bb47-d657bf5b10c1.md) ['windows'] (sigma rule :x:)


### T1569.002
[Execute a Command as a Service](tests/2382dee2-a75f-49aa-9378-f52df6ed3fb1.md) ['windows'] (sigma rule :x:)

[Use PsExec to execute a command on a remote host](tests/873106b7-cfed-454b-8680-fa9f6400431c.md) ['windows'] (sigma rule :x:)


### T1546.014
[Persistance with Event Monitor - emond](tests/23c9c127-322b-4c75-95ca-eff464906114.md) ['macos'] (sigma rule :x:)


### T1070.003
[Clear Bash history (ln dev/null)](tests/23d348f3-cc5c-4ba9-bd0a-ae09069f0914.md) ['linux', 'macos'] (sigma rule :x:)

[Prevent Powershell History Logging](tests/2f898b81-3e97-4abb-bc3f-a95138988370.md) ['windows'] (sigma rule :x:)

[Clear Bash history (truncate)](tests/47966a1d-df4f-4078-af65-db6d9aa20739.md) ['linux'] (sigma rule :x:)

[Use Space Before Command to Avoid Logging to History](tests/53b03a54-4529-4992-852d-a00b4b7215a6.md) ['linux', 'macos'] (sigma rule :x:)

[Disable Bash History Logging with SSH -T](tests/5f8abd62-f615-43c5-b6be-f780f25790a1.md) ['linux'] (sigma rule :x:)

[Clear and Disable Bash History Logging](tests/784e4011-bd1a-4ecd-a63a-8feb278512e6.md) ['linux', 'macos'] (sigma rule :x:)

[Clear history of a bunch of shells](tests/7e6721df-5f08-4370-9255-f06d8a77af4c.md) ['linux', 'macos'] (sigma rule :x:)

[Clear Bash history (rm)](tests/a934276e-2be5-4a36-93fd-98adbb5bd4fc.md) ['linux', 'macos'] (sigma rule :x:)

[Clear Bash history (cat dev/null)](tests/b1251c35-dcd3-4ea1-86da-36d27b54f31f.md) ['linux', 'macos'] (sigma rule :x:)

[Clear Bash history (echo)](tests/cbf506a5-dd78-43e5-be7e-a46b7c7a0a11.md) ['linux'] (sigma rule :x:)

[Clear Powershell History by Deleting History File](tests/da75ae8d-26d6-4483-b0fe-700e4df4f037.md) ['windows'] (sigma rule :x:)


### T1036.003
[Masquerading - wscript.exe running as svchost.exe](tests/24136435-c91a-4ede-9da1-8b284a1c1a23.md) ['windows'] (sigma rule :x:)

[Masquerading - cscript.exe running as notepad.exe](tests/3a2a578b-0a01-46e4-92e3-62e2859b42f0.md) ['windows'] (sigma rule :x:)

[Masquerading as Windows LSASS process](tests/5ba5a3d1-cf3c-4499-968a-a93155d1f717.md) ['windows'] (sigma rule :x:)

[Malicious process Masquerading as LSM.exe](tests/83810c46-f45e-4485-9ab6-8ed0e9e6ed7f.md) ['windows'] (sigma rule :x:)

[Masquerading as Linux crond process.](tests/a315bfff-7a98-403b-b442-2ea1b255e556.md) ['linux'] (sigma rule :x:)

[Masquerading - powershell.exe running as taskhostw.exe](tests/ac9d0fc3-8aa8-4ab5-b11f-682cd63b40aa.md) ['windows'] (sigma rule :x:)

[Masquerading - non-windows exe running as windows exe](tests/bc15c13f-d121-4b1f-8c7d-28d95854d086.md) ['windows'] (sigma rule :x:)

[Masquerading - windows exe running as different windows exe](tests/c3d24a39-2bfe-4c6a-b064-90cd73896cb0.md) ['windows'] (sigma rule :x:)

[File Extension Masquerading](tests/c7fa0c3b-b57f-4cba-9118-863bf4e653fc.md) ['windows'] (sigma rule :x:)


### T1218.008
[Odbcconf.exe - Execute Arbitrary DLL](tests/2430498b-06c0-4b92-a448-8ad263c388e2.md) ['windows'] (sigma rule :x:)


### T1547.001
[Add Executable Shortcut Link to User Startup Folder](tests/24e55612-85f6-4bd6-ae74-a73d02e3441d.md) ['windows'] (sigma rule :x:)

[Suspicious vbs file run from startup Folder](tests/2cb98256-625e-4da9-9d44-f2e5f90b8bd5.md) ['windows'] (sigma rule :x:)

[Reg Key RunOnce](tests/554cbd88-cde1-4b56-8168-0be552eed9eb.md) ['windows'] (sigma rule :x:)

[Suspicious bat file run from startup Folder](tests/5b6768e4-44d2-44f0-89da-a01d1430fd5e.md) ['windows'] (sigma rule :x:)

[Suspicious jse file run from startup Folder](tests/dade9447-791e-4c8f-b04b-3a35855dfa06.md) ['windows'] (sigma rule :x:)

[Reg Key Run](tests/e55be3fd-3521-4610-9d1a-e210e42dcf05.md) ['windows'] (sigma rule :x:)

[PowerShell Registry RunOnce](tests/eb44f842-0457-4ddc-9b92-c4caa144ac42.md) ['windows'] (sigma rule :x:)


### T1110.003
[Password Spray (DomainPasswordSpray)](tests/263ae743-515f-4786-ac7d-41ef3a0d4b2b.md) ['windows'] (sigma rule :x:)

[Password Spray all Domain Users](tests/90bc2e54-6c84-47a5-9439-0a2a92b4b175.md) ['windows'] (sigma rule :x:)

[Password spray all Azure AD users with a single password](tests/a8aa2d3e-1c52-4016-bc73-0f8854cfa80a.md) ['azure-ad'] (sigma rule :x:)

[Password spray all Active Directory domain users with a single password via LDAP against domain controller (NTLM or Kerberos)](tests/f14d956a-5b6e-4a93-847f-0c415142f07d.md) ['windows'] (sigma rule :x:)


### T1216
[SyncAppvPublishingServer Signed Script PowerShell Command Execution](tests/275d963d-3f36-476c-8bef-a2a3960ee6eb.md) ['windows'] (sigma rule :x:)

[manage-bde.wsf Signed Script Command Execution](tests/2a8f2d3c-3dec-4262-99dd-150cb2a4d63a.md) ['windows'] (sigma rule :x:)


### T1574.009
[Execution of program.exe as service with unquoted service path](tests/2770dea7-c50f-457b-84c4-c40a47460d9f.md) ['windows'] (sigma rule :x:)


### T1546.002
[Set Arbitrary Binary as Screensaver](tests/281201e7-de41-4dc9-b73d-f288938cbb64.md) ['windows'] (sigma rule :x:)


### T1033
[Find computers where user has session - Stealth mode (PowerView)](tests/29857f27-a36f-4f7e-8084-4557cd6207ca.md) ['windows'] (sigma rule :x:)

[System Owner/User Discovery](tests/2a9b677d-a230-44f4-ad86-782df1ef108c.md) ['linux', 'macos'] (sigma rule :x:)

[System Owner/User Discovery](tests/4c4959bf-addf-4b4a-be86-8d09cc1857aa.md) ['windows'] (sigma rule :x:)


### T1552.004
[Copy the users GnuPG directory with rsync](tests/2a5a0601-f5fb-4e2e-aa09-73282ae6afca.md) ['macos', 'linux'] (sigma rule :x:)

[Discover Private SSH Keys](tests/46959285-906d-40fa-9437-5a439accd878.md) ['macos', 'linux'] (sigma rule :x:)

[Private Keys](tests/520ce462-7ca7-441e-b5a5-f8347f632696.md) ['windows'] (sigma rule :x:)

[ADFS token signing and encryption certificates theft - Local](tests/78e95057-d429-4e66-8f82-0f060c1ac96f.md) ['windows'] (sigma rule :x:)

[Copy Private SSH Keys with CP](tests/7c247dc7-5128-4643-907b-73a76d9135c3.md) ['linux'] (sigma rule :x:)

[Copy Private SSH Keys with rsync](tests/864bb0b2-6bb5-489a-b43b-a77b3a16d68a.md) ['macos', 'linux'] (sigma rule :x:)

[ADFS token signing and encryption certificates theft - Remote](tests/cab413d8-9e4a-4b8d-9b84-c985bd73a442.md) ['windows'] (sigma rule :x:)


### T1056.002
[PowerShell - Prompt User for Password](tests/2b162bfd-0928-4d4c-9ec3-4d9f88374b52.md) ['windows'] (sigma rule :heavy_check_mark:)

[AppleScript - Prompt User for Password](tests/76628574-0bc1-4646-8fe2-8f4427b47d15.md) ['macos'] (sigma rule :x:)


### T1120
[Win32_PnPEntity Hardware Inventory](tests/2cb4dbf2-2dca-4597-8678-4d39d207a3a5.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1018
[Remote System Discovery - arp](tests/2d5a61f5-0447-4be4-944a-1f8530ed6574.md) ['windows'] (sigma rule :heavy_check_mark:)

[Remote System Discovery - nltest](tests/52ab5108-3f6f-42fb-8ba3-73bc054f22c8.md) ['windows'] (sigma rule :heavy_check_mark:)

[Adfind - Enumerate Active Directory Domain Controller Objects](tests/5838c31e-a0e2-4b9f-b60a-d79d2cb7995e.md) ['windows'] (sigma rule :heavy_check_mark:)

[Remote System Discovery - ping sweep](tests/6db1f57f-d1d5-4223-8a66-55c9c65a9592.md) ['windows'] (sigma rule :x:)

[Remote System Discovery - net](tests/85321a9c-897f-4a60-9f20-29788e50bccd.md) ['windows'] (sigma rule :heavy_check_mark:)

[Remote System Discovery - adidnsdump](tests/95e19466-469e-4316-86d2-1dc401b5a959.md) ['windows'] (sigma rule :x:)

[Remote System Discovery - sweep](tests/96db2632-8417-4dbb-b8bb-a8b92ba391de.md) ['linux', 'macos'] (sigma rule :x:)

[Adfind - Enumerate Active Directory Computer Objects](tests/a889f5be-2d54-4050-bd05-884578748bb4.md) ['windows'] (sigma rule :heavy_check_mark:)

[Remote System Discovery - arp nix](tests/acb6b1ff-e2ad-4d64-806c-6c35fe73b951.md) ['linux', 'macos'] (sigma rule :x:)

[Remote System Discovery - nslookup](tests/baa01aaa-5e13-45ec-8a0d-e46c93c9760f.md) ['windows'] (sigma rule :x:)

[Remote System Discovery - net group Domain Computers](tests/f1bf6c8f-9016-4edf-aff9-80b65f5d711f.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1071.001
[Malicious User Agents - Nix](tests/2d7c471a-e887-4b78-b0dc-b0df1f2e0658.md) ['linux', 'macos'] (sigma rule :x:)

[Malicious User Agents - Powershell](tests/81c13829-f6c9-45b8-85a6-053366d55297.md) ['windows'] (sigma rule :x:)

[Malicious User Agents - CMD](tests/dc3488b0-08c7-4fea-b585-905c83b48180.md) ['windows'] (sigma rule :x:)


### T1053.003
[Cron - Add script to /var/spool/cron/crontabs/ folder](tests/2d943c18-e74a-44bf-936f-25ade6cccab4.md) ['linux'] (sigma rule :x:)

[Cron - Replace crontab with referenced file](tests/435057fb-74b1-410e-9403-d81baf194f75.md) ['macos', 'linux'] (sigma rule :x:)

[Cron - Add script to all cron subfolders](tests/b7d42afa-9086-4c8a-b7b0-8ea3faa6ebb0.md) ['macos', 'linux'] (sigma rule :x:)


### T1053.005
[Scheduled task Remote](tests/2e5eac3e-327b-4a88-a0c0-c4057039a8dd.md) ['windows'] (sigma rule :x:)

[Scheduled task Local](tests/42f53695-ad4a-4546-abb6-7d837f644a71.md) ['windows'] (sigma rule :x:)

[Powershell Cmdlet Scheduled Task](tests/af9fd58f-c4ac-4bf2-a9ba-224b71ff25fd.md) ['windows'] (sigma rule :x:)

[WMI Invoke-CimMethod Scheduled Task](tests/e16b3b75-dc9e-4cde-a23d-dfa2d0507b3b.md) ['windows'] (sigma rule :x:)

[Task Scheduler via VBA](tests/ecd3fa21-7792-41a2-8726-2c5c673414d3.md) ['windows'] (sigma rule :x:)

[Scheduled Task Startup Script](tests/fec27f65-db86-4c2d-b66c-61945aee87c2.md) ['windows'] (sigma rule :x:)


### T1564
[Create a Hidden User Called "$"](tests/2ec63cc2-4975-41a6-bf09-dffdfb610778.md) ['windows'] (sigma rule :x:)

[Create an "Administrator " user (with a space on the end)](tests/5bb20389-39a5-4e99-9264-aeb92a55a85c.md) ['windows'] (sigma rule :x:)

[Extract binary files via VBA](tests/6afe288a-8a8b-4d33-a629-8d03ba9dad3a.md) ['windows'] (sigma rule :x:)


### T1021.001
[Changing RDP Port to Non Standard Port via Powershell](tests/2f840dd4-8a2e-4f44-beb3-6b2399ea3771.md) ['windows'] (sigma rule :x:)

[RDP to DomainController](tests/355d4632-8cb9-449d-91ce-b566d0253d3e.md) ['windows'] (sigma rule :x:)

[RDP to Server](tests/7382a43e-f19c-46be-8f09-5c63af7d3e2b.md) ['windows'] (sigma rule :x:)

[Changing RDP Port to Non Standard Port via Command_Prompt](tests/74ace21e-a31c-4f7d-b540-53e4eb6d1f73.md) ['windows'] (sigma rule :x:)


### T1491.001
[Replace Desktop Wallpaper](tests/30558d53-9d76-41c4-9267-a7bd5184bed3.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1485
[Overwrite deleted data on C drive](tests/321fd25e-0007-417f-adec-33232252be19.md) ['windows'] (sigma rule :heavy_check_mark:)

[macOS/Linux - Overwrite file with DD](tests/38deee99-fd65-4031-bec8-bfa4f9f26146.md) ['linux', 'macos'] (sigma rule :x:)

[Windows - Overwrite file with Sysinternals SDelete](tests/476419b5-aebf-4366-a131-ae3e8dae5fc2.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1546.007
[Netsh Helper DLL Registration](tests/3244697d-5a3a-4dfc-941c-550f69f91a4d.md) ['windows'] (sigma rule :x:)


### T1222.001
[attrib - hide file](tests/32b979da-7b68-42c9-9a99-0e39900fc36c.md) ['windows'] (sigma rule :x:)

[Take ownership using takeown utility](tests/98d34bb4-6e75-42ad-9c41-1dae7dc6a001.md) ['windows'] (sigma rule :x:)

[cacls - Grant permission to specified user or group recursively](tests/a8206bcc-f282-40a9-a389-05d9c0263485.md) ['windows'] (sigma rule :x:)

[Grant Full Access to folder for Everyone - Ryuk Ransomware Style](tests/ac7e6118-473d-41ec-9ac0-ef4f1d1ed2f6.md) ['windows'] (sigma rule :x:)

[attrib - Remove read-only attribute](tests/bec1e95c-83aa-492e-ab77-60c71bbd21b0.md) ['windows'] (sigma rule :x:)


### T1546.008
[Attaches Command Prompt as a Debugger to a List of Target Processes](tests/3309f53e-b22b-4eb6-8fd2-a6cf58b355a9.md) ['windows'] (sigma rule :x:)

[Replace binary of sticky keys](tests/934e90cf-29ca-48b3-863c-411737ad44e3.md) ['windows'] (sigma rule :x:)


### T1098.004
[Modify SSH Authorized Keys](tests/342cc723-127c-4d3a-8292-9c0c6b4ecadc.md) ['macos', 'linux'] (sigma rule :x:)


### T1218.003
[CMSTP Executing Remote Scriptlet](tests/34e63321-9683-496b-bbc1-7566bc55e624.md) ['windows'] (sigma rule :x:)

[CMSTP Executing UAC Bypass](tests/748cb4f6-2fb3-4e97-b7ad-b22635a09ab0.md) ['windows'] (sigma rule :x:)


### T1134.001
[`SeDebugPrivilege` token duplication](tests/34f0a430-9d04-4d98-bcb5-1989f14719f0.md) ['windows'] (sigma rule :x:)

[Named pipe client impersonation](tests/90db9e27-8e7c-4c04-b602-a45927884966.md) ['windows'] (sigma rule :x:)


### T1059.002
[AppleScript](tests/3600d97d-81b9-4171-ab96-e4386506e2c2.md) ['macos'] (sigma rule :x:)


### T1003.008
[Access /etc/shadow (Local)](tests/3723ab77-c546-403c-8fb4-bb577033b235.md) ['linux'] (sigma rule :x:)

[Access /etc/passwd (Local)](tests/60e860b6-8ae6-49db-ad07-5e73edd88f5d.md) ['linux'] (sigma rule :x:)

[Access /etc/{shadow,passwd} with a standard bin that's not cat](tests/df1a55ae-019d-4120-bc35-94f4bc5c4b0a.md) ['linux'] (sigma rule :x:)

[Access /etc/{shadow,passwd} with shell builtins](tests/f5aa6543-6cb2-4fae-b9c2-b96e14721713.md) ['linux'] (sigma rule :x:)


### T1547.011
[Plist Modification](tests/394a538e-09bb-4a4a-95d1-b93cf12682a8.md) ['macos'] (sigma rule :x:)


### T1574.006
[Shared Library Injection via /etc/ld.so.preload](tests/39cb0e67-dd0d-4b74-a74b-c072db7ae991.md) ['linux'] (sigma rule :x:)

[Shared Library Injection via LD_PRELOAD](tests/bc219ff7-789f-4d51-9142-ecae3397deae.md) ['linux'] (sigma rule :x:)


### T1055.012
[RunPE via VBA](tests/3ad4a037-1598-4136-837c-4027e4fa319b.md) ['windows'] (sigma rule :x:)

[Process Hollowing using PowerShell](tests/562427b4-39ef-4e8c-af88-463a78e70b9c.md) ['windows'] (sigma rule :x:)


### T1564.001
[Hidden files](tests/3b7015f2-3144-4205-b799-b05580621379.md) ['macos'] (sigma rule :x:)

[Create a hidden file in a hidden directory](tests/61a782e5-9a19-40b5-8ba4-69a4b9f3d7be.md) ['linux', 'macos'] (sigma rule :x:)

[Show all hidden files](tests/9a1ec7da-b892-449f-ad68-67066d04380c.md) ['macos'] (sigma rule :x:)

[Hide a Directory](tests/b115ecaf-3b24-4ed2-aefe-2fcb9db913d3.md) ['macos'] (sigma rule :x:)

[Mac Hidden file](tests/cddb9098-3b47-4e01-9d3b-6f5f323288a9.md) ['macos'] (sigma rule :x:)

[Create Windows Hidden File with Attrib](tests/dadb792e-4358-4d8d-9207-b771faa0daa5.md) ['windows'] (sigma rule :x:)

[Create Windows System File with Attrib](tests/f70974c8-c094-4574-b542-2c545af95a32.md) ['windows'] (sigma rule :x:)


### T1546.003
[Persistence via WMI Event Subscription](tests/3c64f177-28e2-49eb-a799-d767b24dd1e0.md) ['windows'] (sigma rule :x:)


### T1197
[Bitsadmin Download (cmd)](tests/3c73d728-75fb-4180-a12f-6712864d7421.md) ['windows'] (sigma rule :x:)

[Persist, Download, & Execute](tests/62a06ec5-5754-47d2-bcfc-123d8314c6ae.md) ['windows'] (sigma rule :x:)

[Bits download using desktopimgdownldr.exe (cmd)](tests/afb5e09e-e385-4dee-9a94-6ee60979d114.md) ['windows'] (sigma rule :x:)

[Bitsadmin Download (PowerShell)](tests/f63b8bc4-07e5-4112-acba-56f646f3f0bc.md) ['windows'] (sigma rule :x:)


### T1552.003
[Search Through Bash History](tests/3cfde62b-7c33-4b26-a61e-755d6131c8ce.md) ['linux', 'macos'] (sigma rule :x:)


### T1555.003
[Simulating access to Chrome Login Data](tests/3d111226-d09a-4911-8715-fe11664f960d.md) ['windows'] (sigma rule :heavy_check_mark:)

[Run Chrome-password Collector](tests/8c05b133-d438-47ca-a630-19cc464c4622.md) ['windows'] (sigma rule :heavy_check_mark:)

[LaZagne - Credentials from Browser](tests/9a2915b3-3954-4cce-8c76-00fbf4dbd014.md) ['windows'] (sigma rule :heavy_check_mark:)

[Search macOS Safari Cookies](tests/c1402f7b-67ca-43a8-b5f3-3143abedc01b.md) ['macos'] (sigma rule :x:)


### T1176
[Edge Chromium Addon - VPN](tests/3d456e2b-a7db-4af8-b5b3-720e7c4d9da5.md) ['windows', 'macos'] (sigma rule :x:)

[Chrome (Developer Mode)](tests/3ecd790d-2617-4abf-9a8c-4e8d47da9ee1.md) ['linux', 'windows', 'macos'] (sigma rule :x:)

[Chrome (Chrome Web Store)](tests/4c83940d-8ca5-4bb2-8100-f46dc914bc3f.md) ['linux', 'windows', 'macos'] (sigma rule :x:)

[Firefox](tests/cb790029-17e6-4c43-b96f-002ce5f10938.md) ['linux', 'windows', 'macos'] (sigma rule :x:)


### T1053.006
[Create a user level transient systemd service and timer](tests/3de33f5b-62e5-4e63-a2a0-6fd8808c80ec.md) ['linux'] (sigma rule :x:)

[Create a system level transient systemd service and timer](tests/d3eda496-1fc0-49e9-aff5-3bec5da9fa22.md) ['linux'] (sigma rule :x:)

[Create Systemd Service and Timer](tests/f4983098-bb13-44fb-9b2c-46149961807b.md) ['linux'] (sigma rule :x:)


### T1114.001
[Email Collection with PowerShell Get-Inbox](tests/3f1b5096-0139-4736-9b78-19bcb02bb1cb.md) ['windows'] (sigma rule :x:)


### T1560
[Compress Data for Exfiltration With PowerShell](tests/41410c60-614d-4b9d-b66e-b0192dd9c597.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1562.002
[Kill Event Log Service Threads](tests/41ac52ba-5d5e-40c0-b267-573ed90489bd.md) ['windows'] (sigma rule :x:)

[Impair Windows Audit Log Policy](tests/5102a3a7-e2d7-4129-9e45-f483f2e0eea8.md) ['windows'] (sigma rule :x:)

[Disable Windows IIS HTTP Logging](tests/69435dcf-c66f-4ec0-a8b1-82beb76b34db.md) ['windows'] (sigma rule :x:)

[Clear Windows Audit Policy Config](tests/913c0e4e-4b37-4b78-ad0b-90e7b25010f6.md) ['windows'] (sigma rule :x:)

[Disable Event Logging with wevtutil](tests/b26a3340-dad7-4360-9176-706269c74103.md) ['windows'] (sigma rule :x:)


### T1564.002
[Create Hidden User using UniqueID < 500](tests/4238a7f0-a980-4fff-98a2-dfc0a363d507.md) ['macos'] (sigma rule :x:)

[Create Hidden User using IsHidden option](tests/de87ed7b-52c3-43fd-9554-730f695e7f31.md) ['macos'] (sigma rule :x:)


### T1003.007
[Dump individual process memory with Python (Local)](tests/437b2003-a20d-4ed8-834c-4964f24eec63.md) ['linux'] (sigma rule :x:)

[Dump individual process memory with sh (Local)](tests/7e91138a-8e74-456d-a007-973d67a0bb80.md) ['linux'] (sigma rule :x:)


### T1552.007
[ListSecrets](tests/43c3a49d-d15c-45e6-b303-f6e177e44a9a.md) ['containers'] (sigma rule :x:)

[Cat the contents of a Kubernetes service account token file](tests/788e0019-a483-45da-bcfe-96353d46820f.md) ['linux'] (sigma rule :x:)


### T1505.002
[Install MS Exchange Transport Agent Persistence](tests/43e92449-ff60-46e9-83a3-1a38089df94d.md) ['windows'] (sigma rule :x:)


### T1137.006
[Code Executed Via Excel Add-in File (Xll)](tests/441b1a0f-a771-428a-8af0-e99e4698cda3.md) ['windows'] (sigma rule :x:)


### T1027.004
[Dynamic C# Compile](tests/453614d8-3ba6-4147-acc0-7ec4b3e1faef.md) ['windows'] (sigma rule :x:)

[Go compile](tests/78bd3fa7-773c-449e-a978-dc1f1500bc52.md) ['linux', 'macos'] (sigma rule :x:)

[C compile](tests/d0377aa6-850a-42b2-95f0-de558d80be57.md) ['linux', 'macos'] (sigma rule :x:)

[CC compile](tests/da97bb11-d6d0-4fc1-b445-e443d1346efe.md) ['linux', 'macos'] (sigma rule :x:)

[Compile After Delivery using csc.exe](tests/ffcdbd6a-b0e8-487d-927a-09127fe9a206.md) ['windows'] (sigma rule :x:)


### T1562.003
[Mac HISTCONTROL](tests/468566d5-83e5-40c1-b338-511e1659628d.md) ['macos', 'linux'] (sigma rule :x:)

[Disable history collection](tests/4eafdb45-0f79-4d66-aa86-a3e2c08791f5.md) ['linux', 'macos'] (sigma rule :x:)


### T1546.012
[IFEO Global Flags](tests/46b1f278-c8ee-4aa5-acce-65e77b11f3c1.md) ['windows'] (sigma rule :x:)

[IFEO Add Debugger](tests/fdda2626-5234-4c90-b163-60849a24c0b8.md) ['windows'] (sigma rule :x:)


### T1559.002
[Execute PowerShell script via Word DDE](tests/47c21fb6-085e-4b0d-b4d2-26d72c3830b3.md) ['windows'] (sigma rule :x:)

[DDEAUTO](tests/cf91174c-4e74-414e-bec0-8d60a104d181.md) ['windows'] (sigma rule :x:)

[Execute Commands](tests/f592ba2a-e9e8-4d62-a459-ef63abd819fd.md) ['windows'] (sigma rule :x:)


### T1529
[Restart System via `reboot` - macOS/Linux](tests/47d0b042-a918-40ab-8cf9-150ffe919027.md) ['macos', 'linux'] (sigma rule :x:)

[Shutdown System via `shutdown` - macOS/Linux](tests/4963a81e-a3ad-4f02-adda-812343b351de.md) ['macos', 'linux'] (sigma rule :x:)

[Reboot System via `poweroff` - Linux](tests/61303105-ff60-427b-999e-efb90b314e41.md) ['linux'] (sigma rule :x:)

[Restart System via `shutdown` - macOS/Linux](tests/6326dbc4-444b-4c04-88f4-27e94d0327cb.md) ['macos', 'linux'] (sigma rule :x:)

[Shutdown System via `poweroff` - Linux](tests/73a90cd2-48a2-4ac5-8594-2af35fa909fa.md) ['linux'] (sigma rule :x:)

[Reboot System via `halt` - Linux](tests/78f92e14-f1e9-4446-b3e9-f1b921f2459e.md) ['linux'] (sigma rule :x:)

[Shutdown System via `halt` - Linux](tests/918f70ab-e1ef-49ff-bc57-b27021df84dd.md) ['linux'] (sigma rule :x:)

[Shutdown System - Windows](tests/ad254fa8-45c0-403b-8c77-e00b3d3e7a64.md) ['windows'] (sigma rule :x:)

[Restart System - Windows](tests/f4648f0d-bf78-483c-bafc-3ec99cd1c302.md) ['windows'] (sigma rule :x:)


### T1187
[PetitPotam](tests/485ce873-2e65-4706-9c7e-ae3ab9e14213.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1543.003
[Service Installation PowerShell](tests/491a4af6-a521-4b74-b23b-f7b3f1ee9e77.md) ['windows'] (sigma rule :x:)

[Service Installation CMD](tests/981e2942-e433-44e9-afc1-8c957a1496b6.md) ['windows'] (sigma rule :x:)

[Modify Fax service to run PowerShell](tests/ed366cde-7d12-49df-a833-671904770b9f.md) ['windows'] (sigma rule :x:)


### T1048.002
[Exfiltrate data HTTPS using curl](tests/4a4f31e2-46ea-4c26-ad89-f09ad1d5fe01.md) ['windows', 'macos', 'linux'] (sigma rule :x:)


### T1053.002
[At.exe Scheduled task](tests/4a6c0dc4-0f2a-4203-9298-a5a9bdc21ed8.md) ['windows'] (sigma rule :x:)


### T1556.003
[Malicious PAM rule](tests/4b9dde80-ae22-44b1-a82a-644bf009eb9c.md) ['linux'] (sigma rule :x:)

[Malicious PAM module](tests/65208808-3125-4a2e-8389-a0a00e9ab326.md) ['linux'] (sigma rule :x:)


### T1133
[Running Chrome VPN Extensions via the Registry 2 vpn extension](tests/4c8db261-a58b-42a6-a866-0a294deedde4.md) ['windows'] (sigma rule :x:)


### T1218
[Renamed Microsoft.Workflow.Compiler.exe Payload Executions](tests/4cc40fd7-87b8-4b16-b2d7-57534b86b911.md) ['windows'] (sigma rule :x:)

[InfDefaultInstall.exe .inf Execution](tests/54ad7d5a-a1b5-472c-b6c4-f8090fb2daef.md) ['windows'] (sigma rule :x:)

[Microsoft.Workflow.Compiler.exe Payload Execution](tests/7cbb0f26-a4c1-4f77-b180-a009aa05637e.md) ['windows'] (sigma rule :x:)

[Invoke-ATHRemoteFXvGPUDisablementCommand base test](tests/9ebe7901-7edf-45c0-b5c7-8366300919db.md) ['windows'] (sigma rule :x:)

[Register-CimProvider - Execute evil dll](tests/ad2c17ed-f626-4061-b21e-b9804a6f3655.md) ['windows'] (sigma rule :x:)

[mavinject - Inject DLL into running process](tests/c426dacf-575d-4937-8611-a148a86a5e61.md) ['windows'] (sigma rule :x:)

[SyncAppvPublishingServer - Execute arbitrary PowerShell code](tests/d590097e-d402-44e2-ad72-2c6aa1ce78b1.md) ['windows'] (sigma rule :x:)

[ProtocolHandler.exe Downloaded a Suspicious File](tests/db020456-125b-4c8b-a4a7-487df8afb5a2.md) ['windows'] (sigma rule :x:)


### T1110.004
[SSH Credential Stuffing From Linux](tests/4f08197a-2a8a-472d-9589-cd2895ef22ad.md) ['linux'] (sigma rule :x:)

[SSH Credential Stuffing From MacOS](tests/d546a3d9-0be5-40c7-ad82-5a7d79e1b66b.md) ['macos'] (sigma rule :x:)


### T1057
[Process Discovery - ps](tests/4ff64f0b-aaf2-4866-b39d-38d9791407cc.md) ['macos', 'linux'] (sigma rule :x:)

[Process Discovery - tasklist](tests/c5806a4f-62b8-4900-980b-c7ec004e9908.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1497.001
[Detect Virtualization Environment (Windows)](tests/502a7dc4-9d6f-4d28-abf2-f0e84692562d.md) ['windows'] (sigma rule :x:)

[Detect Virtualization Environment (MacOS)](tests/a960185f-aef6-4547-8350-d1ce16680d09.md) ['macos'] (sigma rule :x:)

[Detect Virtualization Environment (Linux)](tests/dfbd1a21-540d-4574-9731-e852bd6fe840.md) ['linux'] (sigma rule :x:)


### T1036
[System File Copied to Unusual Location](tests/51005ac7-52e2-45e0-bdab-d17c6d4916cd.md) ['windows'] (sigma rule :x:)


### T1046
[Port Scan Nmap](tests/515942b0-a09f-4163-a7bb-22fefb6f185f.md) ['linux', 'macos'] (sigma rule :heavy_check_mark:)

[Port Scan](tests/68e907da-2539-48f6-9fc9-257a78c05540.md) ['linux', 'macos'] (sigma rule :x:)

[Port Scan using python](tests/6ca45b04-9f15-4424-b9d3-84a217285a5c.md) ['windows'] (sigma rule :heavy_check_mark:)

[Port Scan NMap for Windows](tests/d696a3cb-d7a8-4976-8eb5-5af4abf2e3df.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1021.006
[Invoke-Command](tests/5295bd61-bd7e-4744-9d52-85962a4cf2d6.md) ['windows'] (sigma rule :x:)

[Enable Windows Remote Management](tests/9059e8de-3d7d-4954-a322-46161880b9cf.md) ['windows'] (sigma rule :x:)

[WinRM Access with Evil-WinRM](tests/efe86d95-44c4-4509-ae42-7bfd9d1f5b3d.md) ['windows'] (sigma rule :x:)


### T1553.004
[Install root CA on Debian/Ubuntu](tests/53bcf8a0-1549-4b85-b919-010c56d724ff.md) ['linux'] (sigma rule :x:)

[Install root CA on Windows with certutil](tests/5fdb1a7a-a93c-4fbe-aa29-ddd9ef94ed1f.md) ['windows'] (sigma rule :x:)

[Install root CA on Windows](tests/76f49d86-5eb1-461a-a032-a480f86652f1.md) ['windows'] (sigma rule :x:)

[Install root CA on CentOS/RHEL](tests/9c096ec4-fd42-419d-a762-d64cc950627e.md) ['linux'] (sigma rule :x:)

[Install root CA on macOS](tests/cc4a0b8c-426f-40ff-9426-4e10e5bf4c49.md) ['macos'] (sigma rule :x:)


### T1003.004
[Dumping LSA Secrets](tests/55295ab0-a703-433b-9ca4-ae13807de12f.md) ['windows'] (sigma rule :x:)


### T1567
[Data Exfiltration with ConfigSecurityPolicy](tests/5568a8f4-a8b1-4c40-9399-4969b642f122.md) ['windows'] (sigma rule :x:)


### T1098
[Admin Account Manipulate](tests/5598f7cb-cf43-455e-883a-f6008c5d46af.md) ['windows'] (sigma rule :x:)

[AWS - Create a group and add a user to that group](tests/8822c3b0-d9f9-4daf-a043-49f110a31122.md) ['iaas:aws'] (sigma rule :x:)

[Domain Account and Group Manipulate](tests/a55a22e9-a3d3-42ce-bd48-2653adb8f7a9.md) ['windows'] (sigma rule :x:)


### T1610
[Deploy container using nsenter container escape](tests/58004e22-022c-4c51-b4a8-2b85ac5c596b.md) ['linux'] (sigma rule :x:)


### T1127.001
[MSBuild Bypass Using Inline Tasks (C#)](tests/58742c0f-cb01-44cd-a60b-fb26e8871c93.md) ['windows'] (sigma rule :x:)

[MSBuild Bypass Using Inline Tasks (VB)](tests/ab042179-c0c5-402f-9bc8-42741f5ce359.md) ['windows'] (sigma rule :x:)


### T1136.002
[Create a new Domain Account using PowerShell](tests/5a3497a4-1568-4663-b12a-d4a5ed70c7d7.md) ['windows'] (sigma rule :x:)

[Create a new account similar to ANONYMOUS LOGON](tests/dc7726d2-8ccb-4cc6-af22-0d5afb53a548.md) ['windows'] (sigma rule :x:)

[Create a new Windows domain admin user](tests/fcec2963-9951-4173-9bfa-98d8b7834e62.md) ['windows'] (sigma rule :x:)


### T1003.002
[Registry dump of SAM, creds, and secrets](tests/5c2571d0-1572-416d-9676-812e64ca9f44.md) ['windows'] (sigma rule :x:)

[PowerDump Registry dump of SAM for hashes and usernames](tests/804f28fc-68fc-40da-b5a2-e9d0bce5c193.md) ['windows'] (sigma rule :x:)

[dump volume shadow copy hives with System.IO.File](tests/9d77fed7-05f8-476e-a81b-8ff0472c64d0.md) ['windows'] (sigma rule :x:)

[esentutl.exe SAM copy](tests/a90c2f4d-6726-444e-99d2-a00cd7c20480.md) ['windows'] (sigma rule :x:)

[Registry parse with pypykatz](tests/a96872b2-cbf3-46cf-8eb4-27e8c0e85263.md) ['windows'] (sigma rule :x:)

[dump volume shadow copy hives with certutil](tests/eeb9751a-d598-42d3-b11c-c122d9c3f6c7.md) ['windows'] (sigma rule :x:)


### T1547.007
[Re-Opened Applications](tests/5f5b71da-e03f-42e7-ac98-d63f9e0465cb.md) ['macos'] (sigma rule :x:)

[Re-Opened Applications](tests/5fefd767-ef54-4ac6-84d3-751ab85e8aba.md) ['macos'] (sigma rule :x:)


### T1007
[System Service Discovery - net.exe](tests/5f864a3f-8ce9-45c0-812c-bdf7d8aeacc3.md) ['windows'] (sigma rule :heavy_check_mark:)

[System Service Discovery](tests/89676ba1-b1f8-47ee-b940-2e1a113ebc71.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1055.004
[Process Injection via C#](tests/611b39b7-e243-4c81-87a4-7145a90358b1.md) ['windows'] (sigma rule :x:)


### T1558.004
[Rubeus asreproast](tests/615bd568-2859-41b5-9aed-61f6a88e48dd.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1119
[Automated Collection PowerShell](tests/634bd9b9-dc83-4229-b19f-7f83ba9ad313.md) ['windows'] (sigma rule :heavy_check_mark:)

[Recon information for export with Command Prompt](tests/aa1180e2-f329-4e1e-8625-2472ec0bfaf3.md) ['windows'] (sigma rule :x:)

[Recon information for export with PowerShell](tests/c3f6d794-50dd-482f-b640-0384fbb7db26.md) ['windows'] (sigma rule :heavy_check_mark:)

[Automated Collection Command Prompt](tests/cb379146-53f1-43e0-b884-7ce2c635ff5b.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1574.002
[DLL Side-Loading using the Notepad++ GUP.exe binary](tests/65526037-7079-44a9-bda1-2cb624838040.md) ['windows'] (sigma rule :x:)


### T1547.006
[Linux - Load Kernel Module via insmod](tests/687dcb93-9656-4853-9c36-9977315e9d23.md) ['linux'] (sigma rule :x:)


### T1110.002
[Password Cracking with Hashcat](tests/6d27df5d-69d4-4c91-bc33-5983ffe91692.md) ['windows'] (sigma rule :x:)


### T1021.003
[PowerShell Lateral Movement using MMC20](tests/6dc74eb1-c9d6-4c53-b3b5-6f50ae339673.md) ['windows'] (sigma rule :x:)


### T1569.001
[Launchctl](tests/6fb61988-724e-4755-a595-07743749d4e2.md) ['macos'] (sigma rule :x:)


### T1218.009
[Regasm Uninstall Method Call Test](tests/71bfbfac-60b1-4fc0-ac8b-2cedbbdcb112.md) ['windows'] (sigma rule :x:)

[Regsvcs Uninstall Method Call Test](tests/fd3c1c6a-02d2-4b72-82d9-71c527abb126.md) ['windows'] (sigma rule :x:)


### T1053.001
[At - Schedule a job](tests/7266d898-ac82-4ec0-97c7-436075d0d08e.md) ['linux'] (sigma rule :x:)


### T1055.001
[Process Injection via mavinject.exe](tests/74496461-11a1-4982-b439-4d87a550d254.md) ['windows'] (sigma rule :x:)


### T1014
[Loadable Kernel Module based Rootkit](tests/75483ef8-f10f-444a-bf02-62eb0e48db6f.md) ['linux'] (sigma rule :x:)

[Windows Signed Driver Rootkit Test](tests/8e4e1985-9a19-4529-b4b8-b7a49ff87fae.md) ['windows'] (sigma rule :x:)

[Loadable Kernel Module based Rootkit](tests/dfb50072-e45a-4c75-a17e-a484809c8553.md) ['linux'] (sigma rule :x:)


### T1574.012
[Registry-free process scope COR_PROFILER](tests/79d57242-bbef-41db-b301-9d01d9f6e817.md) ['windows'] (sigma rule :x:)

[User scope COR_PROFILER](tests/9d5f89dc-c3a5-4f8a-a4fc-a6ed02e7cb5a.md) ['windows'] (sigma rule :x:)

[System Scope COR_PROFILER](tests/f373b482-48c8-4ce4-85ed-d40c8b3f7310.md) ['windows'] (sigma rule :x:)


### T1137.004
[Install Outlook Home Page Persistence](tests/7a91ad51-e6d2-4d43-9471-f26362f5738e.md) ['windows'] (sigma rule :x:)


### T1048
[Exfiltration Over Alternative Protocol - SSH](tests/7c3cb337-35ae-4d06-bf03-3032ed2ec268.md) ['macos', 'linux'] (sigma rule :x:)

[DNSExfiltration (doh)](tests/c943d285-ada3-45ca-b3aa-7cd6500c6a48.md) ['windows'] (sigma rule :x:)

[Exfiltration Over Alternative Protocol - SSH](tests/f6786cc8-beda-4915-a4d6-ac2f193bb988.md) ['macos', 'linux'] (sigma rule :x:)


### T1059.004
[Create and Execute Bash Shell Script](tests/7e7ac3ed-f795-4fa5-b711-09d6fbe9b873.md) ['macos', 'linux'] (sigma rule :x:)

[Command-Line Interface](tests/d0c88567-803d-4dca-99b4-7ce65e7b257c.md) ['macos', 'linux'] (sigma rule :x:)


### T1040
[Packet Capture Linux](tests/7fe741f7-b265-4951-a7c7-320889083b3e.md) ['linux'] (sigma rule :x:)

[Packet Capture macOS](tests/9d04efee-eff5-4240-b8d2-07792b873608.md) ['macos'] (sigma rule :x:)

[Packet Capture Windows Command Prompt](tests/a5b2f6a0-24b4-493e-9590-c699f75723ca.md) ['windows'] (sigma rule :heavy_check_mark:)

[Windows Internal Packet Capture](tests/b5656f67-d67f-4de8-8e62-b5581630f528.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1036.005
[Execute a process from a directory masquerading as the current parent directory.](tests/812c3ab8-94b0-4698-a9bf-9420af23ce24.md) ['macos', 'linux'] (sigma rule :x:)


### T1574.001
[DLL Search Order Hijacking - amsi.dll](tests/8549ad4b-b5df-4a2d-a3d7-2aee9e7052a3.md) ['windows'] (sigma rule :x:)


### T1552.006
[GPP Passwords (findstr)](tests/870fe8fb-5e23-4f5f-b89d-dd7fe26f3b5f.md) ['windows'] (sigma rule :x:)

[GPP Passwords (Get-GPPPassword)](tests/e9584f82-322c-474a-b831-940fd8b4455c.md) ['windows'] (sigma rule :x:)


### T1098.001
[AWS - Create Access Key and Secret Key](tests/8822c3b0-d9f9-4daf-a043-491160a31122.md) ['iaas:aws'] (sigma rule :x:)

[Azure AD Application Hijacking - App Registration](tests/a12b5531-acab-4618-a470-0dafb294a87a.md) ['azure-ad'] (sigma rule :x:)

[Azure AD Application Hijacking - Service Principal](tests/b8e747c3-bdf7-4d71-bce2-f1df2a057406.md) ['azure-ad'] (sigma rule :x:)


### T1006
[Read volume boot sector via DOS device path (PowerShell)](tests/88f6327e-51ec-4bbf-b2e8-3fea534eab8b.md) ['windows'] (sigma rule :x:)


### T1484.002
[Add Federation to Azure AD](tests/8906c5d0-3ee5-4f63-897a-f6cafd3fdbb7.md) ['azure-ad'] (sigma rule :x:)


### T1036.006
[Space After Filename (Manual)](tests/89a7dd26-e510-4c9f-9b15-f3bae333360f.md) ['macos'] (sigma rule :x:)

[Space After Filename](tests/b95ce2eb-a093-4cd8-938d-5258cef656ea.md) ['macos', 'linux'] (sigma rule :x:)


### T1202
[Indirect Command Execution - forfiles.exe](tests/8b34a448-40d9-4fc3-a8c8-4bb286faf7dc.md) ['windows'] (sigma rule :x:)

[Indirect Command Execution - pcalua.exe](tests/cecfea7a-5f03-4cdd-8bc8-6f7c22862440.md) ['windows'] (sigma rule :x:)

[Indirect Command Execution - conhost.exe](tests/cf3391e0-b482-4b02-87fc-ca8362269b29.md) ['windows'] (sigma rule :x:)


### T1136.003
[AWS - Create a new IAM user](tests/8d1c2368-b503-40c9-9057-8e42f21c58ad.md) ['iaas:aws'] (sigma rule :x:)


### T1012
[Query Registry](tests/8f7578c4-9863-4d83-875c-a565573bbdf0.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1496
[macOS/Linux - Simulate CPU Load with Yes](tests/904a5a0e-fb02-490d-9f8d-0e256eb37549.md) ['macos', 'linux'] (sigma rule :x:)


### T1003
[Gsecdump](tests/96345bfc-8ae7-4b6a-80b7-223200f24ef9.md) ['windows'] (sigma rule :x:)

[Credential Dumping with NPPSpy](tests/9e2173c0-ba26-4cdf-b0ed-8c54b27e3ad6.md) ['windows'] (sigma rule :x:)

[Dump svchost.exe to gather RDP credentials](tests/d400090a-d8ca-4be0-982e-c70598a23de9.md) ['windows'] (sigma rule :x:)


### T1558.001
[Crafting Active Directory golden tickets with mimikatz](tests/9726592a-dabc-4d4d-81cd-44070008b3af.md) ['windows'] (sigma rule :heavy_check_mark:)

[Crafting Active Directory golden tickets with Rubeus](tests/e42d33cd-205c-4acf-ab59-a9f38f6bad9c.md) ['windows'] (sigma rule :x:)


### T1078.001
[Enable Guest account with RDP capability and admin privileges](tests/99747561-ed8d-47f2-9c91-1e5fde1ed6e0.md) ['windows'] (sigma rule :x:)

[Activate Guest Account](tests/aa6cb8c4-b582-4f8e-b677-37733914abda.md) ['windows'] (sigma rule :x:)


### T1106
[Execution through API - CreateProcess](tests/99be2089-c52d-4a4a-b5c3-261ee42c8b62.md) ['windows'] (sigma rule :x:)


### T1546.011
[Application Shim Installation](tests/9ab27e22-ee62-4211-962b-d36d9a0e6a18.md) ['windows'] (sigma rule :x:)

[Registry key creation and/or modification events for SDB](tests/9b6a06f9-ab5e-4e8d-8289-1df4289db02f.md) ['windows'] (sigma rule :x:)

[New shim database files created in the default shim database directory](tests/aefd6866-d753-431f-a7a4-215ca7e3f13d.md) ['windows'] (sigma rule :x:)


### T1562.008
[AWS CloudTrail Changes](tests/9c10dc6b-20bd-403a-8e67-50ef7d07ed4e.md) ['iaas:aws'] (sigma rule :x:)


### T1123
[using device audio capture commandlet](tests/9c3ad250-b185-4444-b5a9-d69218a10c95.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1020
[IcedID Botnet HTTP PUT](tests/9c780d3d-3a14-4278-8ee5-faaeb2ccfbe0.md) ['windows'] (sigma rule :x:)


### T1216.001
[PubPrn.vbs Signed Script Bypass](tests/9dd29a1f-1e16-4862-be83-913b10a88f6c.md) ['windows'] (sigma rule :x:)


### T1563.002
[RDP hijacking](tests/a37ac520-b911-458e-8aed-c5f1576d9f46.md) ['windows'] (sigma rule :x:)


### T1078.003
[Create local account with admin privileges](tests/a524ce99-86de-4db6-b4f9-e08f35a47a15.md) ['windows'] (sigma rule :x:)


### T1546.010
[Install AppInit Shim](tests/a58d9386-3080-4242-ab5f-454c16503d18.md) ['windows'] (sigma rule :x:)


### T1543.001
[Launch Agent](tests/a5983dee-bf6c-4eaf-951c-dbc1a7b90900.md) ['macos'] (sigma rule :x:)


### T1546.005
[Trap](tests/a74b2e07-5952-4c03-8b56-56274b076b61.md) ['macos', 'linux'] (sigma rule :x:)


### T1556.002
[Install and Register Password Filter DLL](tests/a7961770-beb5-4134-9674-83d7e1fa865c.md) ['windows'] (sigma rule :x:)


### T1030
[Data Transfer Size Limits](tests/ab936c51-10f4-46ce-9144-e02137b2016a.md) ['macos', 'linux'] (sigma rule :x:)


### T1552.002
[Enumeration for PuTTY Credentials in Registry](tests/af197fd7-e868-448e-9bd5-05d1bcd9d9e5.md) ['windows'] (sigma rule :heavy_check_mark:)

[Enumeration for Credentials in Registry](tests/b6ec082c-7384-46b3-a111-9a9b8b14e5e7.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1547.005
[Modify SSP configuration in registry](tests/afdfd7e3-8a0b-409f-85f7-886fdf249c9e.md) ['windows'] (sigma rule :x:)


### T1606.002
[Golden SAML](tests/b16a03bc-1089-4dcc-ad98-30fe8f3a2b31.md) ['azure-ad'] (sigma rule :x:)


### T1070
[Indicator Removal using FSUtil](tests/b4115c7a-0e92-47f0-a61e-17e7218b2435.md) ['windows'] (sigma rule :x:)


### T1072
[Radmin Viewer Utility](tests/b4988cad-6ed2-434d-ace5-ea2670782129.md) ['windows'] (sigma rule :x:)


### T1036.004
[Creating W32Time similar named service using sc](tests/b721c6ef-472c-4263-a0d9-37f1f4ecff66.md) ['windows'] (sigma rule :x:)

[Creating W32Time similar named service using schtasks](tests/f9f2fe59-96f7-4a7d-ba9f-a9783200d4c9.md) ['windows'] (sigma rule :x:)


### T1547.004
[Winlogon Shell Key Persistence - PowerShell](tests/bf9f9d65-ee4d-4c3e-a843-777d04f19c38.md) ['windows'] (sigma rule :x:)

[Winlogon Notify Key Logon Persistence - PowerShell](tests/d40da266-e073-4e5a-bb8b-2b385023e5f9.md) ['windows'] (sigma rule :x:)

[Winlogon Userinit Key Persistence - PowerShell](tests/fb32c935-ee2e-454b-8fa3-1c46b42e8dfb.md) ['windows'] (sigma rule :x:)


### T1137
[Office Application Startup - Outlook as a C2](tests/bfe6ac15-c50b-4c4f-a186-0fc6b8ba936c.md) ['windows'] (sigma rule :x:)


### T1543.002
[Create Systemd Service file,  Enable the service , Modify and Reload the service.](tests/c35ac4a8-19de-43af-b9f8-755da7e89c89.md) ['linux'] (sigma rule :x:)

[Create Systemd Service](tests/d9e4f24f-aa67-4c6e-bcbf-85622b697a7c.md) ['linux'] (sigma rule :x:)


### T1137.002
[Office Application Startup Test Persistence](tests/c3e35b58-fe1c-480b-b540-7600fb612563.md) ['windows'] (sigma rule :x:)


### T1547.009
[Shortcut Modification](tests/ce4fc678-364f-4282-af16-2fb4c78005ce.md) ['windows'] (sigma rule :x:)

[Create shortcut to cmd in startup folders](tests/cfdc954d-4bb0-4027-875b-a1893ce406f2.md) ['windows'] (sigma rule :x:)


### T1609
[ExecIntoContainer](tests/d03bfcd3-ed87-49c8-8880-44bb772dea4b.md) ['containers'] (sigma rule :x:)


### T1041
[C2 Data Exfiltration](tests/d1253f6e-c29b-49dc-b466-2147a6191932.md) ['windows'] (sigma rule :x:)


### T1547.010
[Add Port Monitor persistence in Registry](tests/d34ef297-f178-4462-871e-9ce618d44e50.md) ['windows'] (sigma rule :x:)


### T1037.001
[Logon Scripts](tests/d6042746-07d4-4c92-9ad8-e644c114a231.md) ['windows'] (sigma rule :x:)


### T1550.003
[Mimikatz Kerberos Ticket Attack](tests/dbf38128-7ba7-4776-bedf-cc2eed432098.md) ['windows'] (sigma rule :x:)


### T1134.002
[Access Token Manipulation](tests/dbf4f5a9-b8e0-46a3-9841-9ad71247239e.md) ['windows'] (sigma rule :x:)


### T1053.007
[ListCronjobs](tests/ddfb0bc1-3c3f-47e9-a298-550ecfefacbd.md) ['containers'] (sigma rule :x:)

[CreateCronjob](tests/f2fa019e-fb2a-4d28-9dc6-fd1a9b7f68c3.md) ['containers'] (sigma rule :x:)


### T1056.004
[Hook PowerShell TLS Encrypt/Decrypt Messages](tests/de1934ea-1fbf-425b-8795-65fb27dd7e33.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1550.002
[crackmapexec Pass the Hash](tests/eb05b028-16c8-4ad8-adea-6f5b219da9a9.md) ['windows'] (sigma rule :x:)

[Mimikatz Pass the Hash](tests/ec23cef9-27d9-46e4-a68d-6f75f7b86908.md) ['windows'] (sigma rule :x:)


### T1037.002
[Logon Scripts - Mac](tests/f047c7de-a2d9-406e-a62b-12a09d9516f4.md) ['macos'] (sigma rule :x:)


### T1564.003
[Hidden Window](tests/f151ee37-9e2b-47e6-80e4-550b9f999b7a.md) ['windows'] (sigma rule :x:)


### T1574.011
[Service ImagePath Change with reg.exe](tests/f38e9eea-e1d7-4ba6-b716-584791963827.md) ['windows'] (sigma rule :x:)

[Service Registry Permissions Weakness](tests/f7536d63-7fd4-466f-89da-7e48d550752a.md) ['windows'] (sigma rule :x:)


### T1553.001
[Gatekeeper Bypass](tests/fb3d46c6-9480-4803-8d7d-ce676e1f1a9b.md) ['macos'] (sigma rule :x:)


### T1010
[List Process Main Windows - C# .NET](tests/fe94a1c3-3e22-4dc9-9fdf-3a8bdbc10dc4.md) ['windows'] (sigma rule :heavy_check_mark:)


### T1027.001
[Pad Binary to Change Hash - Linux/macOS dd](tests/ffe2346c-abd5-4b45-a713-bf5f1ebd573a.md) ['macos', 'linux'] (sigma rule :x:)

