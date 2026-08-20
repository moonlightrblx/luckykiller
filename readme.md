> (=^･ω･^=)
> lucky killer readme

## overview

lucky killer is a specialized python security and mitigation utility built for windows . it scans local drives, neutralizes threats, blocks c2 network traffic, and cleans corrupted visual studio project files.
we specifically target luckyware. 
---

## features
* auto-elevates to administrator privileges on startup
* automatically installs required dependencies (`pefile`, `yara-python`, `colorama`)
* blocks c2 domains via hosts file modification and adds windows firewall outbound rules
* scans and removes malware binaries, temp droppers, and build files
* sanitizes `.vcxproj`, `.csproj`, and `.sln` files by stripping malicious build events and injected properties
---

## usage

run the script directly from an elevated terminal:

```bash
python luckykiller.py

```

## menu options

* **1** - full scan and clean (recommended scans, cleans threats, and blocks c2 network)


* **2** - full scan report only (detects threats and outputs a report without modifying files)


* **3** - block c2 network only (updates hosts file and firewall rules immediately)


* **4** - kill malicious processes (terminates active malicious tasks)


* **5** - scan specific folder (targets a custom directory to analyze)


* **6** - dry run preview mode (simulates cleaning actions safely without touching files)


* **0** - exit
