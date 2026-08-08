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

Covers the four Android architecture layers (Linux Kernel, Native Libraries, Application Framework, Application Layer).

![Android architecture layers diagram](task3-01.png)

Covers the Android filesystem partition structure (`system/`, `data/`, `sdcard/`, `vendor/`, `dev/proc/sys`).

![Android filesystem layers diagram](task3-02.png)

💡 The `build.prop` file in the `system` partition stores device build metadata, including serial number — a quick artifact for device identification.

To examine the evidence image, open FTK Imager and go to File → Add Evidence Item:

![Add Evidence Item menu in FTK Imager](task3-03.png)

Select the Image File option:

![Selecting Image File option](task3-04.png)

Select the `Suspicious_device.ad1` file from `/Desktop/Evidence`:

![Selecting Suspicious_device.ad1](task3-05.png)

Navigate through the loaded evidence to get an overview of the artifacts:

![Navigating the loaded image in FTK Imager](task3-06.gif)

**Q: Navigate the directories in FTK Imager. Examine the build.prop file found in the system folder. What is the device's serial number?**
```
ABC123456789
```
![build.prop showing device serial number](task3-07.png)

## Task 4 — Android - Forensic Artifacts

Catalog of key Android forensic artifacts and their locations:

**SMS/MMS & Call Logs** — communications artifacts, crucial for reconstructing conversations and timelines.

Location: `/data/data/com.android.providers.telephony/databases/mmssms.db` (SMS/MMS)

![mmssms.db location](task4-01.png)

Location: `/data/data/com.android.providers.contacts/databases/calllog.db` (Call Logs)

![calllog.db location](task4-02.png)

**Contacts & Address Book** — identifies social connections and associates.

Location: `/data/data/com.android.providers.contacts/databases/contacts2.db`

![contacts2.db location](task4-03.png)

**Browser History** — reveals internet usage habits, search intent, and accessed web services.

Location (Chrome): `/data/data/com.android.chrome/app_chrome/Default/History`

![Chrome History file location](task4-04.png)

**Location Data** — maps user movements and frequented places.

Location: `/data/data/com.google.android.gms/databases/` (`location.db`, `networklocations.db`, etc.)

**Photos, Videos & Metadata** — provides visual timelines, EXIF geolocation/timestamps.

Location: `/sdcard/DCIM/`, `/sdcard/Pictures/`, `/sdcard/WhatsApp/Media/`

![WhatsApp media directory](task4-05.png)

**Instant Messaging Apps** — direct evidence of conversations and shared media.

Location: `/data/data/com.whatsapp/databases/msgstore.db`, `/sdcard/WhatsApp/Media/`

**Application Data** — custom logs, usage traces, cached credentials, background activity.

Location: `/data/data/[app.package.name]/` (e.g. `com.instagram.android`, `com.snapchat.android`)

![Instagram app data directory example](task4-06.png)

**User Accounts & Google Services** — identifies linked identities and syncing/exfiltration vectors.

Location: `/data/system/users/0/accounts.db`, `/data/data/com.google.android.gms/databases`

![accounts.db location](task4-07.png)

**Installed Applications Information** — app metadata, permissions, install/uninstall timeline.

Location: `/data/system/packages.xml`

🔴 Lists dangerous permissions and install timestamps — directly relevant when hunting for surveillance tools or exfiltration-capable apps.

![packages.xml content](task4-08.png)

**Q: Examine the artifact containing information about the device's installed apps. What is the last package installed on this device?**
```
com.sneakcam.capture
```
![Last installed package in packages.xml](task4-09.png)

## Task 5 — Tools for the Trade

Covers acquisition levels (Logical, File System, Physical) and tooling: ALEAPP, Autopsy + Android Modules, Cellebrite UFED, Magnet AXIOM, Oxygen Forensic Detective, ADB, TWRP Recovery, LiME, Andriller, ADB-Backup Extractors, Protobuf Parsers. No answers required.

## Task 6 — Unboxing the Artifacts

Manual examination of artifacts via `sqlite3` against the evidence at `Desktop\Evidence\suspicious_device`.

![Suspicious_device evidence folder structure](task6-01.png)

**SMS / MMS**

Located at `...\data\data\com.android.providers.telephony\databases\mmssms.db`:

![mmssms.db file location](task6-02.png)

```
sqlite3 mmssms.db
```

![Opening mmssms.db in sqlite3](task6-03.png)

Run `.tables` to list tables, then `select * from SMS;`:

![SMS table query output](task6-04.png)

Use `.mode line` to display each column on a separate line:

![.mode line output](task6-05.png)

Use `.mode box` for a neat tabular format:

![.mode box output](task6-06.png)

**Call Logs**

Located at `...\data\data\com.android.providers.contacts\databases\calllog.db`:

![calllog.db file location](task6-07.png)

```
sqlite3 calllog.db
```

![Opening calllog.db in sqlite3](task6-08.png)

Run `.tables`, then `SELECT * from calls;`:

![calls table query output](task6-09.png)

**Contacts and Address Book**

Load `contacts2.db` from the same `com.android.providers.contacts\databases\` path:

![Opening contacts2.db in sqlite3](task6-10.png)

Run `.tables`, then `select * from data;`:

![data table query output showing contacts](task6-11.png)

**Browser History**

Only Chrome artifacts are present in this evidence, meaning it was the only browser installed:

![Chrome-only browser artifacts present](task6-12.png)

`History.db` located at `...\data\data\com.android.chrome\app_chrome\Default`:

![History.db file location](task6-13.png)

```
sqlite3 History
.tables
```

![History.db tables listed](task6-14.png)

Run `SELECT * from URLs;`:

![URLs table query output](task6-15.png)

**Bluetooth Information**

Config file at `data\misc\bluedroid`, reviewed as text with `find`:

![Bluetooth config file contents](task6-16.png)

**WIFI Information**

Config file at `data\misc\wifi`:

![Wi-Fi config file contents](task6-17.png)

🔴 Manual artifact-by-artifact review is thorough but time-consuming — sets up the case for automated triage in Task 7.

**Q: What is the flag hidden inside SMS?**
```
FLAG{MSG_HIDDEN_INTENT}
```
![Flag hidden inside SMS message](task6-18.png)

**Q: In the call logs, which number has the longest call duration?**
```
+14155550011
```
![Call log entry with longest duration](task6-19.png)

**Q: What is the second-to-last suspicious contact name in the list?**
```
Encrypted User
```
![Second-to-last suspicious contact name](task6-20.png)

**Q: Most Chrome searches indicate that the user was looking for sites to upload data. What is the last URL found in the list for a similar purpose?**
```
https://easyupload.io
```
![Last suspicious upload-related URL](task6-21.png)

**Q: What is the name of the Bluetooth device found in the configuration?**
```
Pixel_6_User
```
![Bluetooth device name in configuration](task6-22.png)

## Task 7 — Triaging with ALEAPP

ALEAPP (Android Logs Events and Protobuf Parser) automates artifact extraction from an Android image/archive, running 30+ plugins and compiling a structured report.

ALEAPP is located on the Desktop:

![ALEAPP folder on Desktop](task7-01.png)

Launch the GUI version:
```
python aleappGUI.py
```
![ALEAPP GUI launched](task7-02.png)

Select `suspicious_device.zip` from `Desktop/Evidence` as the evidence file, set the output directory, and select all plugins:

![Selecting suspicious_device.zip as evidence](task7-03.png)
![Running plugins against the evidence](task7-04.gif)

**Call Logs** — review for suspicious entries:

![ALEAPP report - Call Logs](task7-05.png)
![ALEAPP report - Call Logs detail](task7-06.png)

**Installed Packages** — hunt for suspicious/exfiltration-capable packages:

![ALEAPP report - Installed Packages](task7-07.png)

**SMS / MMS Messages** — structured view of message content:

![ALEAPP report - SMS/MMS Messages](task7-08.png)

**Chrome Data** — search history reveals suspect intent:

![ALEAPP report - Chrome Data](task7-09.png)
![ALEAPP report - Chrome search intent](task7-10.png)

**Download History** — metadata from `downloads.db` at `\data\data\com.android.providers.downloads\databases\`:

![ALEAPP report - Download History](task7-11.png)

🔴 ALEAPP surfaced a data-exfiltration-capable package and MMS/download artifacts that were not caught during the manual pass in Task 6 — reinforcing the value of automated triage alongside manual review.

**Q: What is the name of the package found that could be used for the data exfiltration?**
```
com.data.exfiltool
```
![Suspicious exfiltration package name](task7-12.png)

**Q: One of the MMS message indicates the website used to send the sensitive file? What is the name of that site?**
```
MediaFire
```
![MMS message referencing MediaFire](task7-13.png)

**Q: In the contacts, what is the email address associated with the suspicious user named "Encrypted User"?**
```
ghost123@tutanota.com
```
![Encrypted User contact email address](task7-14.png)

**Q: A sensitive PDF document was found on the device. Examine the document in the downloads folder. What is the flag hidden inside it?**
```
FLAG{INSIDER_ACCESS_42X9}
```
![Flag hidden inside downloaded PDF](task7-15.png)

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