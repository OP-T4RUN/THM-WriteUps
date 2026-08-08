| Room | Platform | Path | Module | Difficulty | Category |
|------|----------|------|--------|------------|----------|
| [Android Analysis](https://tryhackme.com/room/androidanalysis) | TryHackMe | Advanced Endpoint Investigations | Mobile Analysis | Easy | Digital Forensics |

**Author:** [OPT4RUN](https://tryhackme.com/p/OPT4RUN)

## Overview

This room walks through forensic examination of an Android device image using FTK Imager, sqlite3, and ALEAPP. The scenario involves an employee, Hazem, suspected of exfiltrating sensitive company documents via his Android device. From a SOC/blue-team perspective, this room reinforces the Android filesystem layout, key artifact locations (SMS/MMS, call logs, contacts, browser history, Bluetooth/Wi-Fi configs, installed packages), and how to triage those artifacts both manually and using an automated parser (ALEAPP) — directly applicable to insider-threat and data-exfiltration investigations.

## Task 1 — Introduction

Scenario setup: Hazem is suspected of selling company secrets via his Android device. No answers required.

## Task 2 — Lab Connection

Lab machine setup; evidence image `Suspicious_device.ad1` located in `Desktop/Evidence`. No answers required.

## Task 3 — Android Architecture - An Overview

Covers the four Android architecture layers (Linux Kernel, Native Libraries, Application Framework, Application Layer) and the Android filesystem partition structure (`system/`, `data/`, `sdcard/`, `vendor/`, `dev/proc/sys`).

💡 The `build.prop` file in the `system` partition stores device build metadata, including serial number — a quick artifact for device identification.

![FTK Imager evidence tree](task3-01.png)
![Android filesystem layers diagram](task3-02.png)
![Add Evidence Item menu in FTK Imager](task3-03.png)
![Selecting Image File option](task3-04.png)
![Selecting Suspicious_device.ad1](task3-05.png)
![Navigating the loaded image in FTK Imager](task3-06.gif)
![build.prop showing device serial number](task3-07.png)

**Q: Navigate the directories in FTK Imager. Examine the build.prop file found in the system folder. What is the device's serial number?**
```
ABC123456789
```

## Task 4 — Android - Forensic Artifacts

Catalog of key Android forensic artifacts and their locations:

| Artifact | Location |
|----------|----------|
| SMS/MMS | `/data/data/com.android.providers.telephony/databases/mmssms.db` |
| Call Logs | `/data/data/com.android.providers.contacts/databases/calllog.db` |
| Contacts | `/data/data/com.android.providers.contacts/databases/contacts2.db` |
| Browser History (Chrome) | `/data/data/com.android.chrome/app_chrome/Default/History` |
| Location Data | `/data/data/com.google.android.gms/databases/` |
| Photos/Videos | `/sdcard/DCIM/`, `/sdcard/Pictures/`, `/sdcard/WhatsApp/Media/` |
| WhatsApp | `/data/data/com.whatsapp/databases/msgstore.db` |
| App Data | `/data/data/[app.package.name]/` |
| Accounts/Google Services | `/data/system/users/0/accounts.db`, `/data/data/com.google.android.gms/databases` |
| Installed Apps | `/data/system/packages.xml` |

🔴 Installed application metadata (`packages.xml`) lists dangerous permissions and install timestamps — directly relevant when hunting for surveillance tools or exfiltration-capable apps.

![mmssms.db location](task4-01.png)
![calllog.db location](task4-02.png)
![contacts2.db location](task4-03.png)
![Chrome History file location](task4-04.png)
![WhatsApp media directory](task4-05.png)
![Instagram app data directory example](task4-06.png)
![accounts.db location](task4-07.png)
![packages.xml content](task4-08.png)
![Last installed package in packages.xml](task4-09.png)

**Q: Examine the artifact containing information about the device's installed apps. What is the last package installed on this device?**
```
com.sneakcam.capture
```

## Task 5 — Tools for the Trade

Covers acquisition levels (Logical, File System, Physical) and tooling: ALEAPP, Autopsy + Android Modules, Cellebrite UFED, Magnet AXIOM, Oxygen Forensic Detective, ADB, TWRP Recovery, LiME, Andriller, ADB-Backup Extractors, Protobuf Parsers. No answers required.

## Task 6 — Unboxing the Artifacts

Manual examination of artifacts via `sqlite3` against the evidence at `Desktop\Evidence\suspicious_device`:

- **SMS/MMS** — `sqlite3 mmssms.db` → `.tables` → `select * from SMS;` (with `.mode line` / `.mode box` display options)
- **Call Logs** — `sqlite3 calllog.db` → `.tables` → `SELECT * from calls;`
- **Contacts** — `sqlite3 contacts2.db` → `.tables` → `select * from data;`
- **Browser History** — `sqlite3 History` → `.tables` → `SELECT * from URLs;`
- **Bluetooth** — config file at `data\misc\bluedroid` (reviewed as text)
- **Wi-Fi** — config file at `data\misc\wifi` (reviewed as text)

🔴 Manual artifact-by-artifact review is thorough but time-consuming — sets up the case for automated triage in Task 7.

![Suspicious_device evidence folder structure](task6-01.png)
![mmssms.db file location](task6-02.png)
![Opening mmssms.db in sqlite3](task6-03.png)
![SMS table query output](task6-04.png)
![.mode line output](task6-05.png)
![.mode box output](task6-06.png)
![calllog.db file location](task6-07.png)
![Opening calllog.db in sqlite3](task6-08.png)
![calls table query output](task6-09.png)
![Opening contacts2.db in sqlite3](task6-10.png)
![data table query output showing contacts](task6-11.png)
![Chrome-only browser artifacts present](task6-12.png)
![History.db file location](task6-13.png)
![History.db tables listed](task6-14.png)
![URLs table query output](task6-15.png)
![Bluetooth config file contents](task6-16.png)
![Wi-Fi config file contents](task6-17.png)
![Flag hidden inside SMS message](task6-18.png)
![Call log entry with longest duration](task6-19.png)
![Second-to-last suspicious contact name](task6-20.png)
![Last suspicious upload-related URL](task6-21.png)
![Bluetooth device name in configuration](task6-22.png)

**Q: What is the flag hidden inside SMS?**
```
FLAG{MSG_HIDDEN_INTENT}
```

**Q: In the call logs, which number has the longest call duration?**
```
+14155550011
```

**Q: What is the second-to-last suspicious contact name in the list?**
```
Encrypted User
```

**Q: Most Chrome searches indicate that the user was looking for sites to upload data. What is the last URL found in the list for a similar purpose?**
```
https://easyupload.io
```

**Q: What is the name of the Bluetooth device found in the configuration?**
```
Pixel_6_User
```

## Task 7 — Triaging with ALEAPP

ALEAPP (Android Logs Events and Protobuf Parser) automates artifact extraction from an Android image/archive, running 30+ plugins and compiling a structured report (Call Logs, Installed Packages, SMS/MMS, Chrome Data, Download History, etc.), invoked via `python aleappGUI.py` against `suspicious_device.zip`.

🔴 ALEAPP surfaced a data-exfiltration-capable package and MMS/download artifacts that were not caught during the manual pass in Task 6 — reinforcing the value of automated triage alongside manual review.

![ALEAPP folder on Desktop](task7-01.png)
![ALEAPP GUI launched](task7-02.png)
![Selecting suspicious_device.zip as evidence](task7-03.png)
![Running plugins against the evidence](task7-04.gif)
![ALEAPP report - Call Logs](task7-05.png)
![ALEAPP report - Call Logs detail](task7-06.png)
![ALEAPP report - Installed Packages](task7-07.png)
![ALEAPP report - SMS/MMS Messages](task7-08.png)
![ALEAPP report - Chrome Data](task7-09.png)
![ALEAPP report - Chrome search intent](task7-10.png)
![ALEAPP report - Download History](task7-11.png)
![Suspicious exfiltration package name](task7-12.png)
![MMS message referencing MediaFire](task7-13.png)
![Encrypted User contact email address](task7-14.png)
![Flag hidden inside downloaded PDF](task7-15.png)

**Q: What is the name of the package found that could be used for the data exfiltration?**
```
com.data.exfiltool
```

**Q: One of the MMS message indicates the website used to send the sensitive file? What is the name of that site?**
```
MediaFire
```

**Q: In the contacts, what is the email address associated with the suspicious user named "Encrypted User"?**
```
ghost123@tutanota.com
```

**Q: A sensitive PDF document was found on the device. Examine the document in the downloads folder. What is the flag hidden inside it?**
```
FLAG{INSIDER_ACCESS_42X9}
```

## Task 8 — Framing Questions

Introduces the 5Ws + H method for structuring investigations, with three scenario walkthroughs: insider data theft (WhatsApp/communication apps), malicious website access/cybercrime (browser/VPN artifacts), and malware infection/device compromise (installed apps, permissions, logs). No answers required.

## Task 9 — Recap and Conclusion

Summary of room content. No answers required.

## Key Takeaways

- Android's layered architecture (Kernel → Native Libraries → Framework → Application) directly maps to where forensic artifacts live on disk
- `build.prop` yields quick device identification (serial number, model, build info)
- Core artifact locations to memorize: `mmssms.db`, `calllog.db`, `contacts2.db`, Chrome `History`, `packages.xml`, Bluetooth/Wi-Fi configs under `data/misc/`
- `sqlite3` with `.tables` and `.mode` (line/box/etc.) is sufficient for manual SQLite artifact review
- ALEAPP automates and accelerates triage across 30+ artifact types, and can surface exfiltration-related packages/messages missed during manual review
- Framing investigative questions with the 5Ws + H method before diving into artifacts keeps insider-threat, cybercrime, and malware-compromise investigations focused

---

*Write-up by [OPT4RUN](https://tryhackme.com/p/OPT4RUN)*