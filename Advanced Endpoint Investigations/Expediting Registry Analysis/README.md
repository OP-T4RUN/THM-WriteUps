# Expediting Registry Analysis

| Field | Details |
|-------|---------|
| **Platform** | TryHackMe |
| **Path** | Advanced Endpoint Investigations |
| **Module** | Windows Endpoint Investigation |
| **Difficulty** | Medium |
| **Category** | Digital Forensics / IR |
| **Room Link** | [tryhackme.com/room/expregistryforensics](https://tryhackme.com/room/expregistryforensics) |
| **Author** | [OPT4RUN](https://tryhackme.com/p/OPT4RUN) |

---

## Overview

This room builds on the foundational registry knowledge from Windows Forensics 1 and shifts focus to **operational registry analysis** — how to acquire, process, and interrogate registry hives quickly during an incident. The scenario follows Anna, an IR lead at Deer Inc., investigating suspicious activity flagged by an unexpected user account creation.

From a SOC/blue team perspective, this room is highly practical. It covers both the deliberate (cold) and time-pressured (live) collection paths, then walks through three complementary toolsets — FTK Imager, KAPE, and EZTools/RegRipper — each suited to different phases and constraints of an investigation. The final challenge applies these skills against a second compromised system, reinforcing the workflow end-to-end.

---

## Task 1 — Introduction

The room focuses on four investigation objectives Anna wants to answer from registry data:

- System identification information
- User accounts, including any suspicious ones
- Password resets and failed login attempts
- Networks the system has previously connected to

**Prerequisites:** Windows Forensics 1, KAPE room, SOC Level 1 & 2 paths.

---

## Task 2 — Data Acquisition: Considerations and FTK Imager

### Live vs Cold Acquisition

| Factor | Live Acquisition | Cold Acquisition |
|--------|-----------------|-----------------|
| System state | Running | Powered off |
| Registry files | Locked — requires special tools | Accessible via disk image |
| Speed | Fast | Slow (full disk image first) |
| Impact on system | Leaves traces (e.g. program execution entries) | Minimal — works from write-blocked image |
| Best for | Time-critical incidents | Court-ready evidence, integrity preservation |

> 💡 **Tip:** In a live system, executing any tool (including FTK Imager) adds entries to execution-tracking registry keys. Account for this contamination in your analysis.

### FTK Imager — Registry Extraction

FTK Imager can extract registry hives from both live and cold systems. The key difference is the evidence source:

- **Live system** → Add Evidence Item → **Logical Drive** (e.g. C:)
- **Cold image** → Add Evidence Item → **Image File** → browse to disk image

![FTK Imager Add Evidence Item dialog](task2-01.png)

![Selecting Logical Drive for live acquisition](task2-02.png)

![Selecting the OS drive from available drives](task2-03.png)

![Selecting Image File for cold acquisition](task2-04.png)

![Browsing to the disk image file](task2-05.png)

**Option 1 — Obtain Protected Files:** A quick way to grab locked registry files in a live system, but limited in scope — notably excludes the Amcache hive.

![FTK Imager Obtain Protected Files option](task2-06.png)

**Option 2 — Manual navigation and Export Files:** More complete. Manually browse the directory tree, select hives, transaction logs (`.LOG1`, `.LOG2`), and backup files, then export. Works for both live and cold collections.

> 🔴 **Malware relevance:** Always collect transaction logs alongside hives. These contain changes not yet written to the main hive file — skipping them means potentially missing recent attacker activity.

![Manually exporting registry hives and transaction logs from FTK Imager](task2-07.png)

**Q: When we take a forensic data collection from the disk image of a system, what type of acquisition is it called?**
```
cold acquisition
```

**Q: Is speed one of the advantages of collecting registry data from FTK Imager? Y or N?**
```
N
```

---

## Task 3 — Data Acquisition Using KAPE

### Why KAPE Over FTK Imager?

FTK Imager requires manual navigation and is operator-dependent. KAPE automates the collection, reduces human error, is scriptable, and is suitable for enterprise-scale deployment via batch mode.

### KAPE GUI — Registry Collection

1. Launch `gkape.exe` from the KAPE folder
2. Enable **Use Target Options**
3. Set **Target source** (C: for live; mounted image drive for cold)
4. Set **Target destination**
5. Select the **RegistryHives** target (or `KapeTriage` for a broader package)
6. Click **Execute!**

![KAPE GUI with Target Options enabled](task3-01.png)

![Selecting Target source and destination in KAPE](task3-02.png)

![Selecting the RegistryHives target in KAPE](task3-03.png)

![KAPE executing collection in command window](task3-04.png)

![KAPE execution complete message](task3-05.png)

> 💡 **Tip:** KAPE preserves the original directory structure and file metadata in its output — forensically important for maintaining chain of custody and for tools that rely on file paths.

![KAPE output directory structure](task3-06.png)

### Batch Mode — `_kape.cli`

For delegated or remote collection, create a `_kape.cli` file containing the KAPE command (without `.\kape.exe`). Place it in the KAPE directory. Anyone with admin rights can run `kape.exe` and the collection executes automatically, including optional SCP upload to an IR staging server.

![KAPE batch mode _kape.cli execution](task3-07.png)

**Q: What will be the contents of a `_kape.cli` file if we want to collect data from the C drive and save it to the D drive using the target RegistryHives?**
```
--tsource C: --tdest D:\ --target RegistryHives
```

---

## Task 4 — Registry Analysis Using EZTools

### Registry Explorer (GUI)

Registry Explorer loads raw hive files and integrates transaction logs interactively. Key workflow:

1. **File > Load hive** → select the hive (e.g. SYSTEM from KAPE output)
2. When prompted, click **Yes** to integrate transaction logs → select matching `.LOG1`/`.LOG2` files
3. Save the clean hive to a new location (default: `HIVE_clean`)
4. Reload the clean hive when prompted
5. Use the **Available bookmarks** tab for quick access to forensically important keys

![Registry Explorer initial window](task4-01.png)

![Loading the SYSTEM hive into Registry Explorer](task4-02.png)

![Transaction log integration prompt](task4-03.png)

![Selecting SYSTEM transaction log files](task4-04.png)

![Saving the clean hive](task4-05.png)

![Prompt to reload with transaction log data applied](task4-06.png)

![Available Bookmarks tab showing ComputerName key highlighted](task4-07.png)

![Multiple hives loaded simultaneously in Registry Explorer](task4-08.png)

**Key SYSTEM hive paths for system identification:**

| Artefact | Registry Path |
|----------|--------------|
| Computer Name | `ControlSet001\Control\ComputerName\ComputerName` |
| Current Control Set | `SYSTEM\Select\Current` |
| Time Zone | `SYSTEM\CurrentControlSet\Control\TimeZoneInformation` |
| Network Interfaces | `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces` |

### RECmd (Command Line)

RECmd is the CLI counterpart to Registry Explorer. Useful for scripted extraction and batch processing. Key capabilities:

- Search hives by key name (`--sk`), key path (`--kn`), or string value
- Supports regex, BASE64, Unicode, ASCII search modes
- Recovers deleted keys/values
- Outputs to CSV or JSON
- **Batch mode** via YAML file — pre-defined key extraction mapped to categories, normalised CSV output

> 🔴 **Malware relevance:** RECmd batch mode can extract UserAssist and Amcache data into a single "Program Execution" CSV — invaluable for quickly reconstructing what ran on a compromised host.

**Q: What is the Computer Name of the computer we are analysing?**
```
4N6
```

![Registry Explorer showing ComputerName value as 4N6](task4-09.png)

**Q: What is the TimeZoneKeyName of the computer we are analysing?**
```
UTC
```

![Registry Explorer showing TimeZoneKeyName value as UTC](task4-10.png)

**Q: What is the LastKnownGood control set of the system?**
```
2
```

![Registry Explorer showing LastKnownGood value as 2](task4-11.png)

---

## Task 5 — Registry Analysis Using RegRipper

### RegRipper

RegRipper (`rr.exe` for GUI, `rip.exe` for CLI) uses community-built plugins to extract and format forensically important registry values into readable text output. Each plugin targets specific keys; if a key doesn't exist or no plugin covers it, it won't appear in output.

> ⚠️ **Critical:** RegRipper does **not** integrate transaction logs. Always pre-process dirty hives in Registry Explorer first, then feed the clean hive to RegRipper.

### SAM Hive Analysis — User Accounts

![RegRipper initial interface with transaction log warning](task5-01.png)

![Selecting the SAM hive in RegRipper](task5-02.png)

![RegRipper output window after parsing SAM hive](task5-03.png)

![RegRipper output files in destination directory](task5-04.png)

![RegRipper parsed output showing user account details](task5-05.png)

The SAM hive output includes per-account: Last Login Date, Password Reset Date, Login Count, RID, and group membership — all aggregated without manual key navigation.

**Q: Which account was created last?**
```
suspicious
```

![RegRipper output showing 'suspicious' account as most recently created](task5-06.png)

**Q: What is the Password Reset Date of this account?**
```
2024-03-03 11:51:04Z
```

**Q: What is the RID of the account 4n6lab?**
```
1008
```

![RegRipper output showing RID 1008 for 4n6lab account](task5-07.png)

**Q: Which 3 accounts are part of the Administrators group? (ascending order of RID)**
```
administrator, 4n6lab, suspicious
```

![RegRipper output showing Administrators group membership](task5-08.png)
![RegRipper output showing 4n6lab account details](task5-07.png)
![RegRipper output showing suspicious account details](task5-06.png)
![RegRipper output showing Administrator account details](task5-09.png)

---

## Task 6 — Speeding Up Analysis Using KAPE and EZTools

### Combined Acquisition + Processing in One Pass

KAPE can run target collection and module processing in the same execution. For registry analysis:

- **Target:** `RegistryHives`
- **Module:** `!EZParser` (uses RECmd batch mode under the hood)

KAPE automatically uses the target destination as the module source, so no additional path configuration is needed.

![KAPE GUI showing combined target and module options](task6-01.png)

![RegistryHives target selected in KAPE](task6-02.png)

![!EZParser module selected in KAPE](task6-03.png)

![KAPE executing combined acquisition and processing](task6-04.png)

![KAPE module output directory structure](task6-05.png)

> 💡 **Tip:** `!EZParser` automatically integrates transaction logs into each hive during processing — one of its key advantages over running RegRipper manually.

### Analysing Network Artefacts from CSV Output

Navigate to: `[Module Destination]\Registry\[Date]\`

![Registry CSV output files including KnownNetworks and NetworkAdapters](task6-06.png)

The `KnownNetworks` CSV contains: network name, network type, first/last connection dates, DNS suffix, and gateway MAC address — all in a single row per network.

![KnownNetworks CSV opened in EZViewer showing network connection details](task6-07.png)

**Q: What is the network's gateway MAC address, which was last connected in 2021?**
```
0A-41-2A-ED-DB-34
```

**Q: When was this network last connected?**
```
3/17/2021 14:59
```

**Q: When was "Network 2" first connected?**
```
3/17/2021 15:08
```

![KnownNetworks CSV showing all three network answers highlighted](task6-10.png)

### Bonus — Full Forensic Package

Swap `RegistryHives` target for `KapeTriage` (all critical artefacts: MFT, Prefetch, registry, etc.) with the same `!EZParser` module for a comprehensive triage output covering most Windows forensic artefact categories.

![KAPE with KapeTriage target selected for full forensic package](task6-08.png)

![!EZParser module selected alongside KapeTriage target](task6-09.png)

---

## Task 7 — Practical Challenge

A second potentially compromised system — artefacts placed in the `James` folder on the Desktop. Tooling choice is open.

**Q: What is the name of this system?**
```
JAMES
```

![Registry showing ComputerName as JAMES](task7-01.png)

**Q: Which user, other than administrator, is part of the administrators group?**
```
art-test
```

![Registry showing Administrators group membership for James system](task7-02.png)
![SAM hive output confirming art-test account details](task7-03.png)

**Q: A VPN connection was established on this system. What was the name of the network that connected to a VPN?**
```
ProtonVPN
```

![KnownNetworks CSV showing ProtonVPN network entry](task7-04.png)

**Q: To which organization is the Windows OS registered?**
```
Amazon.com
```

![SOFTWARE hive showing RegisteredOrganization as Amazon.com](task7-05.png)

---

## Key Takeaways

- **Live vs Cold acquisition** is a trade-off between speed and forensic integrity. Live collections leave traces; cold collections from write-blocked images are court-defensible but time-intensive.
- **Transaction logs (`.LOG1`, `.LOG2`)** must always be merged into hives before analysis — they contain recent changes not yet committed to the hive file. Registry Explorer handles this cleanly; RegRipper does not.
- **FTK Imager** gives granular, file-by-file control over what gets collected — best when you need to target specific hives precisely.
- **KAPE** automates and scales collection; batch mode (`_kape.cli`) enables delegation to sysadmins or remote execution with SCP upload — critical during outbreaks.
- **`!EZParser` module in KAPE** processes all collected artefacts in one pass, auto-integrates transaction logs, and outputs normalised CSV files — the fastest path from raw hives to analysable data.
- **Registry Explorer** is the go-to for interactive hive exploration and transaction log integration; the **Available Bookmarks** tab shortcuts to the highest-value forensic keys.
- **RECmd batch mode** enables reproducible, structured extraction via YAML — useful for standardising what gets pulled across multiple investigations.
- **RegRipper** trades flexibility for speed — plugin-based parsing produces readable text reports quickly, but is limited to keys its plugins cover and cannot process dirty hives independently.
- The **SAM hive** surfaces account creation timestamps, RIDs, password reset dates, and group membership — first-stop for identifying rogue accounts (`suspicious` account, RID sequence anomalies).
- **KnownNetworks CSV** (from `!EZParser`) reconstructs network connection history including gateway MAC, first/last seen timestamps, and network type — useful for identifying VPN usage or lateral movement paths.
- Cross-artefact attack chain reconstruction: rogue account in SAM (`suspicious`) + VPN network in KnownNetworks + OS registration anomaly (Amazon.com → likely cloud/VM) builds a picture of a potentially attacker-controlled machine enrolled in a corporate environment.

---

*Write-up by [OPT4RUN](https://tryhackme.com/p/OPT4RUN)*