# Windows Memory & Processes

| | |
|---|---|
| **Room** | [Windows Memory & Processes](https://tryhackme.com/room/windowsmemoryandprocs) |
| **Difficulty** | Medium |
| **Path** | Advanced Endpoint Investigations |
| **Module** | Memory Analysis |

## Overview

This is the first room in a three-part series (Processes → User Activity → Network) that walks through a full, realistic memory-dump investigation rather than isolated plugin demos. For a SOC/blue team analyst, this is where the earlier Volatility Essentials plugin knowledge gets applied against a real incident: a full Windows memory dump from an internal case, where the goal is extracting processes, linking them into an attack chain, and reporting findings — exactly the workflow expected when handed a triage image from IR.

## Task 1 — Introduction

No questions. Frames memory analysis as a manual, structured skill — tools like Volatility and Redline extract data, but the analyst still has to interpret and link it. Sets objectives: extract processes/process info via Volatility, analyze the results, and report findings.

## Task 2 — Scenario Information

🔴 **Incident THM-0001** — TryHatMe (an online hat retailer) escalated an incident at 07:30 CET on May 5, 2025. Initial triage flagged a potentially compromised Windows host:

- **Hostname:** WIN-001
- **OS:** Windows 10 22H2, build 10.0.19045

At 07:45 CET, analyst Steve Stevenson captured a full memory dump and hashed it for integrity:

- **Filename:** `THM-WIN-001_071528_07052025.dmp`
- **MD5:** `78535fc49ab54fed57919255709ae650`

task2-01.png

## Task 3 — Windows Processes Architecture

Before diving into the dump, the room covers the four kernel/user-space structures Volatility's plugins actually target:

| Structure | Location | Purpose |
|---|---|---|
| **EPROCESS** | Kernel | Represents a process |
| **ETHREAD** | Kernel | Represents a thread |
| **PEB** (Process Environment Block) | User space | Process-wide config and runtime data |
| **TEB** (Thread Environment Block) | User space | Thread-specific config, TLS, exception handling, stack info |

task3-01.png

### How they relate

When Windows runs `CreateProcess()`:

1. The kernel creates an `EPROCESS` and `ETHREAD` and links them (`EPROCESS.ThreadListHead` tracks all threads)
2. Virtual memory is initialized — address space assigned, image mapped, PEB/TEB space allocated, process parameters created
3. PEB and TEB are initialized: `EPROCESS` points to PEB, `ETHREAD` points to TEB, and TEB holds a redundant pointer back to PEB
4. Thread context (start address, stack pointer, instruction pointer) is set while the process remains suspended
5. The primary thread resumes — this is the actual start of the process

task3-02.png

### What each structure exposes

**EPROCESS** — targeted by `pslist`, `pstree`, `psscan`, `malfind`, `getsids`, `handles`, `dlllist`, `cmdline`, `envars`, `ldrmodules`:

```c
struct _EPROCESS {
    HANDLE UniqueProcessId;           // PID
    LIST_ENTRY ActiveProcessLinks;    // Link in active process list
    UCHAR ImageFileName[15];          // Short process name
    LARGE_INTEGER CreateTime;         // Process creation time
    LARGE_INTEGER ExitTime;           // Exit time if terminated
    PPEB Peb;                         // Pointer to user-mode PEB
    HANDLE InheritedFromUniqueProcessId; // Parent PID
    LIST_ENTRY ThreadListHead;        // List of ETHREADs
    PHANDLE_TABLE ObjectTable;        // Handle table (opened files)
    PVOID SectionObject;              // Executable image mapping
    PVOID VadRoot;                    // VAD tree for memory mapping
    PACCESS_TOKEN Token;              // Security information
}
```

**ETHREAD** — targeted by `threads`, `ldrmodules`, `apihooks`, `malfind`:

```c
struct _ETHREAD {
    CLIENT_ID Cid;                    // Thread and Process IDs
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;
    PVOID StartAddress;               // Kernel-level entry point
    PVOID Win32StartAddress;          // User-mode entry point
    LIST_ENTRY ThreadListEntry;       // Link in EPROCESS's thread list
    PTEB Teb;                         // Pointer to TEB
    ULONG ThreadState;
    ULONG WaitReason;
}
```

**PEB** — targeted by `cmdline`, `envars`, `ldrmodules`, `malfind`:

```c
struct _PEB {
    BOOLEAN BeingDebugged;
    PVOID ImageBaseAddress;           // Base address of executable
    PPEB_LDR_DATA Ldr;                // Loader data (DLLs)
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters; // Command-line, env vars
    ULONG NtGlobalFlag;
    PVOID ProcessHeap;
}
```

**TEB** — targeted by `threads`, `malfind`:

```c
struct _TEB {
    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ThreadLocalStoragePointer;  // TLS base
    PPEB ProcessEnvironmentBlock;
    ULONG LastErrorValue;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID Win32ThreadInfo;
}
```

### Q&A

**What field is used to keep track of all the active processes?**
```
ActiveProcessLinks
```

**What field is used to store the PID of a process?**
```
UniqueProcessId
```

## Task 4 — Initial Triage of a New Memory Dump

**Lab:** Ubuntu Desktop with Volatility 3 (aliased as `vol3`), plus `strings`, `diff`, `grep`, `comm`, `awk`.

### Verifying the dump

```bash
ubuntu@tryhackme:~$ md5sum THM-WIN-001_071528_07052025.mem > newhash.txt
ubuntu@tryhackme:~$ diff acquisitionhash.txt newhash.txt
```
No output from `diff` = hashes match, integrity confirmed.

### Extracting processes

| Plugin | Purpose |
|---|---|
| `windows.pslist` | Active processes at capture time |
| `windows.psscan` | All process objects, including terminated/unlinked |
| `windows.pstree` | Active processes with parent-child relationships |
| `windows.psxview` | Cross-references multiple detection techniques (processes, threads, handles) |

```bash
ubuntu@tryhackme:~$ vol3 -f THM-WIN-001_071528_07052025.mem windows.pslist > pslist.txt
ubuntu@tryhackme:~$ cat pslist.txt | less
```

### Hunting for suspicious processes

🔴 Three indicator categories to watch for:

- **Suspicious name** — typosquatting: `scvhost.exe`, `explorere.exe`, `lsasss.exe`
- **Suspicious path** — legitimate names running from the wrong location: `svchost.exe` from `C:\Users\analyst\` instead of `C:\Windows\System32\`
- **Masquerading** — plausible-sounding fake service names: `dockerupdater.exe`, `defenderAV.exe`, `pdfupdateservice.exe`

### Baselining

1. Establish a baseline of normal-operation processes
2. Diff `pslist` output against the baseline
3. Filter out known software-update processes (check Task Scheduler)
4. Investigate what's left

```bash
ubuntu@tryhackme:~$ awk 'NR >3{print $2}' baseline/baseline.txt | sort | uniq > baseline_procs.txt
ubuntu@tryhackme:~$ awk 'NR >3{print $3}' pslist.txt | sort | uniq > current_procs.txt
ubuntu@tryhackme:~$ comm -13 baseline_procs.txt current_procs.txt
```

`comm -13` shows lines unique to `current_procs.txt`. Some hits are false positives — legitimate processes absent from the baseline capture, or names truncated by `ImageFileName`'s 16-byte limit. After filtering, three processes made the shortlist:

| ImageFileName | PID | Timestamp |
|---|---|---|
| `pdfupdater.exe` | 3392 | 2025-05-07 07:13:05 |
| `windows-update.exe` | 10084 | 2025-05-07 07:13:05 |
| `updater.exe` | 10032 | 2025-05-07 07:13:56 |

### Q&A

**What is the PID of the csrss.exe process that has 12 threads?**
```
440
```
task4-01.png

**What is the (memory) Offset(V) of the process with PID 5672?**
```
0x990b29293080
```
task4-02.png

## Task 5 — Linking Processes

Before digging into individual process memory, map how the suspicious processes relate to each other and to the rest of the tree — this surfaces additional suspects that weren't flagged on their own.

Reference attack-chain shape from the room:
```
explorer.exe (PID: 1500)
└── cmd.exe (PID: 2200)                  ← Triggered by malicious LNK file
    └── powershell.exe (PID: 2210)       ← Downloads and executes the payload
        └── svchost.exe (PID: 2220)      ← Masquerades as a system process
            └── asyncrat.exe (PID: 2230) ← Remote Access Trojan (C2 beaconing)
```

```bash
ubuntu@tryhackme:~$ vol3 -f THM-WIN-001_071528_07052025.mem windows.pstree > processtree.txt
ubuntu@tryhackme:~$ cut -d$'\t' -f1,2,3 processtree.txt
```

### Observed chain

```
PID     PPID    IMAGENAME
5252    5672    WINWORD.EXE
└── 3392   5252    pdfupdater.exe
    ├── 2576   3392    conhost.exe
    └── 10084  3392    windows-update
        └── 10032  10084   updater.exe
            └── 432    10032   cmd.exe
                ├── 4592   432     conhost.exe
                └── 6984   432     powershell.exe
```

| ImageFileName | PID | PPID | Timestamp |
|---|---|---|---|
| WINWORD.EXE | 5252 | 5672 | 2025-05-07 07:13:04 |
| pdfupdater.exe | 3392 | 5252 | 2025-05-07 07:13:05 |
| conhost.exe | 2576 | 3392 | 2025-05-07 07:13:05 |
| windows-update.exe | 10084 | 3392 | 2025-05-07 07:13:05 |
| updater.exe | 10032 | 10084 | 2025-05-07 07:13:56 |
| cmd.exe | 432 | 10032 | 2025-05-07 07:14:36 |
| conhost.exe | 4592 | 432 | 2025-05-07 07:14:36 |
| powershell.exe | 6984 | 432 | 2025-05-07 07:14:39 |

🔴 Reasoning for suspicion:
- Multiple processes carry "update" in their name
- WINWORD.exe launching `pdfupdater.exe` implies Word is updating a PDF tool — already odd
- `pdfupdater.exe` then launches `windows-update.exe` — a PDF-updater triggering a Windows OS update makes no sense
- `windows-update.exe` in turn launches `updater.exe` — yet another "update" layer
- The presence of `conhost.exe` siblings hints at network-connection activity

### Q&A

**What is the parentID (PPID) of the services.exe (PID 664) process?**
```
524
```
task5-01.png

**What is the ImageFileName of the process that has the PID 7788?**
```
FTK Imager.exe
```
task5-02.png

## Task 6 — Digging Deeper

Volatility can also surface terminated, unlinked, or hidden processes — techniques attackers use to conceal processes, threads, drivers, and registry keys.

### PSSCAN vs PSLIST

```bash
ubuntu@tryhackme:~$ vol3 -f THM-WIN-001_071528_07052025.mem windows.psscan > psscan.txt
ubuntu@tryhackme:~$ awk '{print $1,$3}' pslist.txt | sort > pslist_processed.txt
ubuntu@tryhackme:~$ awk '{print $1,$3}' psscan.txt | sort > psscan_processed.txt
ubuntu@tryhackme:~$ comm -23 psscan_processed.txt pslist_processed.txt
```

Output listed common processes (`svchost.exe`, `sihost.exe`, `ctfmon.exe`, `vmtoolsd.exe`, `taskhostw.exe`) — all benign in this case. 💡 To verify `svchost.exe`-style hits are legitimate, check: image path (should be `C:\Windows\System32\`), loaded DLLs (rule out hollowing/injection), whether active threads exist despite absence from `pslist`, whether an active process has zero threads (every legitimate process has ≥1), and whether Exit Time is populated for processes claimed as terminated.

### PSXVIEW

Cross-references multiple detection techniques in one pass:

```bash
ubuntu@tryhackme:~$ vol3 -f THM-WIN-001_071528_07052025.mem windows.psxview > psxview.txt
ubuntu@tryhackme:~$ awk 'NR==3 || $4 == "False"' psxview.txt
```

No new suspicious processes surfaced from `psscan`/`psxview` in this case — the previously identified chain remains the focus.

### Q&A

**What is the number of processes that have 0 Threads?**
```
3
```
task6-01.png

**What is the number of processes that have the Exit Time filled in?**
```
3
```
task6-02.png

## Task 7 — Dumping the Process Memory

`windows.dlllist` and `windows.dumpfiles` help confirm suspicions by extracting the actual executable paths and file content.

### Finding executable paths

```bash
ubuntu@tryhackme:~$ vol3 -f THM-WIN-001_071528_07052025.mem windows.dlllist --pid 5252 > 5252_dlllist.txt
ubuntu@tryhackme:~$ cat 5252_dlllist.txt
```

🔴 `pdfupdater.exe`, `windows-update.exe`, and `updater.exe` all start from unusual (user-writable) locations — a strong persistence/execution red flag.

### Dumping process memory

```bash
ubuntu@tryhackme:~$ mkdir 5252
ubuntu@tryhackme:~$ cd 5252
ubuntu@tryhackme:~/5252$ vol3 -f ../THM-WIN-001_071528_07052025.mem windows.dumpfiles --pid 5252
```

Dumped files follow the pattern `file.StartAddress.EndAddress.ImageSectionObject.filename.img` or `...DataSectionObject.filename.dat`.

| | ImageSectionObject | DataSectionObject |
|---|---|---|
| **Purpose** | Mapped executable image | Mapped data |
| **Typical content** | .exe, .dll, injected PE files | Configs, logs, unpacked payloads |
| **Executable?** | Yes | Usually no |

💡 What to filter for, by process type:
- Word process → `.docm`/`.dotm`/`.dotx` (macro-based VBA execution — MITRE T1059.005)
- Suspiciously-named process → `.exe`/`.dat` pairs, then `strings` for function names, URLs, IPs, system commands
- PDF reader process → `.pdf` files, then `strings` for embedded JavaScript (MITRE T1059.007)

```bash
ubuntu@tryhackme:~$ ls 5252 | grep -E ".docm|.dotm" -i
file.0x990b2ae077d0.0x990b2a3f5d70.SharedCacheMap.Normal.dotm.vacb
file.0x990b2ae077d0.0x990b2b916cd0.DataSectionObject.Normal.dotm.dat
file.0x990b2ae0ab60.0x990b28043a00.SharedCacheMap.cv-resume-test.docm.vacb
file.0x990b2ae0ab60.0x990b2a8b4b30.DataSectionObject.cv-resume-test.docm.dat

ubuntu@tryhackme:~$ file 5252/file.0x990b2ae077d0.0x990b2b916cd0.DataSectionObject.Normal.dotm.dat
5252/file.0x990b2ae077d0.0x990b2b916cd0.DataSectionObject.Normal.dotm.dat: Microsoft Word 2007+
```

```bash
ubuntu@tryhackme:~$ ls 3392 10084 10032 | grep -E ".exe|.dat" -i
file.0x990b2ae26720.0x990b286fa140.ImageSectionObject.updater.exe.img
file.0x990b2846e310.0x990b282f5b70.DataSectionObject.cversions.2.db.dat
file.0x990b2ae16230.0x990b29ad0270.ImageSectionObject.windows-update.exe.img
file.0x990b2ae16230.0x990b2b92ce90.DataSectionObject.windows-update.exe.dat
file.0x990b2ae0ee90.0x990b2a466010.ImageSectionObject.pdfupdater.exe.img
file.0x990b2ae0ee90.0x990b2b91f290.DataSectionObject.pdfupdater.exe.dat
```

### Consolidated findings

| PID | PPID | Timestamp | Path | Files |
|---|---|---|---|---|
| 5252 | 5672 | 2025-05-07 07:13:04 | `C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE` | `cv-resume-test.docm.dat`, `Normal.dotm.dat` |
| 3392 | 5252 | 2025-05-07 07:13:05 | `C:\Users\operator\pdfupdater.exe` | `pdfupdater.exe.img`, `pdfupdater.exe.dat` |
| 2576 | 3392 | 2025-05-07 07:13:05 | `??\C:\Windows\system32\conhost.exe` | / |
| 10084 | 3392 | 2025-05-07 07:13:05 | `C:\Users\operator\AppData\Roaming\Microsoft\Windows\StartMenu\Programs\Startup\windows-update.exe` | `windows-update.exe.img`, `windows-update.exe.dat` |
| 10032 | 10084 | 2025-05-07 07:13:56 | `C:\Users\operator\Downloads\updater.exe` | `updater.exe.img` |
| 432 | 10032 | 2025-05-07 07:14:36 | `C:\Windows\system32\cmd.exe` | / |
| 4592 | 432 | 2025-05-07 07:14:36 | `??\C:\Windows\system32\conhost.exe` | / |
| 6984 | 432 | 2025-05-07 07:14:39 | `powershell` | / |

### Q&A

**What is the path of the process with PID 7788?**
```
C:\Program Files\AccessData\FTK Imager\FTK Imager.exe
```
task7-01.png

**Dump the process with PID 7788. What is the name of the dumped file that represents the executable?**
```
file.0x990b2ae1ed40.0x990b29954a20.ImageSectionObject.FTK Imager.exe.img
```
task7-02.png

## Task 8 — Putting It All Together

task8-01.png

Mapping the gathered artifacts onto a kill chain, using MITRE ATT&CK:

| Phase | Detail | MITRE Technique |
|---|---|---|
| **Initial Access** | Likely a malicious macro-enabled Word document (needs user-activity confirmation) | T1566 Phishing |
| **Execution** | `WINWORD.exe` opens `cv-resume-test.docm`/`Normal.dotm`, which likely downloads and launches `pdfupdater.exe` | T1059.005 Command and Scripting Interpreter: Visual Basic |
| **Persistence** | `pdfupdater.exe` downloads `windows-update.exe`, staged in the Startup folder | T1037.005 Boot or Logon Initialization Scripts: Startup Items |
| **Command and Control** | `windows-update.exe`'s persistence suggests it functions as a C2 client or reverse shell (needs further analysis) | — |
| **Unplaced** | `updater.exe`, spawned by the likely-C2 `windows-update.exe` — purpose unconfirmed; plausibly Exfiltration, Impact, Discovery, or Lateral Movement | TA0010 / TA0040 / TA0007 / TA0008 |

📌 The dump alone can't confirm Initial Access — that needs corroboration from user-activity analysis, which the next room in this series covers.

### Q&A

**What is the name of the likely compromised user?**
```
operator
```
task8-02.png

**What is the ID assigned to the MITRE Tactic Command and Control?**
```
TA0011
```

## Task 9 — Conclusion

Wraps up the first room in the three-part memory series. A potential attack chain and multiple suspicious artifacts were uncovered purely from process analysis; the next steps — covered in the following two rooms — are analyzing user activity and network activity from the same dump.

## Key Takeaways

- EPROCESS/ETHREAD/PEB/TEB aren't just academic — knowing which structure each plugin reads from explains why certain fields (PID, parent PID, command line, loaded DLLs) come from different modules
- `pslist` alone isn't enough for triage — baselining against normal operation, then filtering out update/scheduled-task noise, is what actually narrows a large process list down to real suspects
- A multi-hop "update" process chain (`pdfupdater.exe` → `windows-update.exe` → `updater.exe`) is a textbook masquerading pattern — each hop individually looks plausible, but the full chain doesn't match any legitimate update behavior
- `psscan`/`psxview` cross-referencing is the check for hidden/unlinked processes — but a clean result doesn't rule out compromise, it just means nothing was hidden via unlinking in this case
- `ImageSectionObject` vs `DataSectionObject` distinguishes executable memory-mapped content from data/config content when dumping process memory — know which one you need before filtering dump output
- Process-only analysis can establish Execution, Persistence, and a C2 hypothesis, but Initial Access and the full purpose of downstream binaries (like `updater.exe`) require corroboration from other data sources — hence the room being part 1 of 3

---
*Write-up by OPT4RUN*