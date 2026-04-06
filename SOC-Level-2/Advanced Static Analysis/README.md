# Advanced Static Analysis

| Field | Details |
|-------|---------|
| **Room** | Advanced Static Analysis |
| **Platform** | TryHackMe |
| **Path** | SOC Level 2 |
| **Module** | Malware Analysis |
| **Difficulty** | Medium |
| **Category** | Malware Analysis |
| **Room Link** | [tryhackme.com/room/advancedstaticanalysis](https://tryhackme.com/room/advancedstaticanalysis) |
| **Author** | [OPT4RUN](https://tryhackme.com/p/OPT4RUN) |

---

## Overview

Building on the foundations of Basic Static Analysis — strings, hashes, PE headers, import tables — this room moves into **reverse engineering**: reading compiled assembly and decompiled pseudo-C to understand malware behavior without ever executing it.

The primary tool throughout is **Ghidra**, an open-source reverse engineering framework developed by the NSA. The room covers:
- Setting up Ghidra projects and navigating its core panels
- Recognizing common C code constructs (loops, conditionals, functions) in assembly
- Identifying categories of suspicious Windows API calls
- End-to-end analysis of a **process hollowing** sample (`Benign.exe`)

🔴 **Malware relevance:** Advanced static analysis is the technique used when malware is obfuscated, packed, or too complex for basic static tools to reveal intent. Reading disassembly and decompiled pseudo-C is a core skill for any SOC L2 analyst performing triage on suspicious binaries.

---

## Task 1 — Introduction

This room is a direct continuation of the SOC Level 2 Malware Analysis path. Prerequisites:
- [x86 Architecture Overview](https://tryhackme.com/room/x8664arch)
- [x86 Assembly Crash Course](https://tryhackme.com/room/x86assemblycrashcourse)
- [Basic Static Analysis](https://tryhackme.com/room/staticanalysis1)

---

## Task 2 — Malware Analysis: Overview

The four stages of malware analysis:

| Stage | Executes Malware? | Focus |
|-------|-------------------|-------|
| Basic Static | ❌ | File structure, strings, hashes, imports |
| Basic Dynamic | ✅ | Runtime behavior in a sandbox |
| Advanced Static | ❌ | Disassembly, decompilation, deobfuscation |
| Advanced Dynamic | ✅ | Complex evasion, detailed runtime tracing |

Advanced static analysis aims to uncover **hidden or obfuscated code** by analyzing the compiled binary directly with disassemblers and decompilers. Common tools: IDA Pro, Binary Ninja, radare2, Ghidra.

**Q: Does advanced static analysis require executing the malware in a controlled environment?**
```
nay
```

---

## Task 3 — Connecting to the VM

The VM comes pre-loaded with a full reverse engineering toolkit:

![VM Desktop showing Ghidra, x32dbg, x64dbg, IDA Free, Cutter, PE-bear, pestudio, Benign.exe, HelloWorld.exe and Code_Constructs folder](task3-01.png)

| Tool | Purpose |
|------|---------|
| Ghidra | Primary disassembler / decompiler (used in this room) |
| x32dbg / x64dbg | Debuggers for dynamic analysis |
| IDA Free | Alternative disassembler |
| Cutter | GUI frontend for radare2 |
| PE-bear / pestudio | PE header and import analysis |

**Q: I have successfully connected to the VM.**
```
No answer needed
```

**Q: How many files are present in the Code_Constructs folder on the Desktop?**
```
5
```

---

## Task 4 — Ghidra: A Quick Overview

### Setting Up a Project

Ghidra requires a project before any binary can be loaded for analysis.

**Step 1 — Ghidra opens with no active project**

![Ghidra project manager showing NO ACTIVE PROJECT state](task4-01.png)

**Step 2 — File → New Project**

![Ghidra File menu with New Project option highlighted](task4-02.png)

**Step 3 — Select Non-Shared Project**

![New Project dialog with Non-Shared Project radio button selected](task4-03.png)

💡 **Tip:** Non-Shared keeps analysis local. Shared Project enables collaborative analysis — useful when multiple SOC analysts are working the same incident.

**Step 4 — Name the project**

![Project location dialog with project named HelloWorld and directory set to C:\Users\Administrator](task4-04.png)

**Step 5 — Drag & Drop the target executable into the project**

![HelloWorld.exe being dragged from the Desktop into the active Ghidra HelloWorld project](task4-05.png)

**Step 6 — Review the Import Results Summary**

Ghidra auto-detects file format, architecture, language ID, and hashes before any analysis begins.

![Import Results Summary for HelloWorld.exe showing MD5 hash, architecture x86 LE 32, compiler visualstudio and file metadata](task4-06.png)

**Step 7 — Open in Code Browser and click Yes to analyze**

![Code Browser with analyze prompt asking whether to analyze HelloWorld.exe now](task4-07.png)

**Step 8 — Leave analysis options at defaults and click Analyze**

![Analysis Options dialog showing the full list of enabled and disabled analyzers with the Analyze button highlighted](task4-08.png)

---

### Exploring the Ghidra Layout

![Annotated Ghidra Code Browser layout with 6 numbered callouts identifying each panel](task4-09.png)

| # | Panel | Purpose |
|---|-------|---------|
| 1 | Program Trees | PE sections (`.text`, `.data`, `.rdata`, etc.) — click any section to jump to it |
| 2 | Symbol Tree | Imports, Exports, Functions — the starting point for most analysis |
| 3 | Data Type Manager | Data structures and types found in the binary |
| 4 | Listing | Disassembly view — virtual address, opcode, instruction, operands, comments |
| 5 | Decompiler | Pseudo-C translation of the selected function |
| 6 | Toolbar | Graph view, memory map, navigation controls |

**Function Graph** — visualizes the control flow graph (CFG) of a function, showing how basic blocks connect via conditional and unconditional jumps:

![Function Graph view showing connected code blocks for the if-else.exe program](task4-10.png)

**Memory Map** — shows all PE sections with their virtual addresses, sizes, and read/write/execute permissions:

![Memory Map window showing Headers, .text, .rdata, .data, .rsrc, .reloc sections with start addresses, lengths, and permission flags](task4-11.png)

**Navigation Toolbar** — back/forward navigation through analyzed code, similar to a browser history:

![Ghidra navigation toolbar showing back, forward, and other navigation controls](task4-12.png)

**Search for Strings** (`Search → For Strings`) — extracts human-readable strings from the binary:

![String Search window showing 1605 items found in HelloWorld.exe with location, label, and string view columns](task4-13.png)

🔴 **Malware relevance:** String search is often the fastest path to C2 addresses, file paths, registry keys, mutex names, and hardcoded credentials embedded in malware.

---

### Analyzing HelloWorld.exe in Assembly

Clicking `.text` in Program Trees and scrolling to the MessageBox call shows both the disassembly and its decompiled equivalent side by side:

![.text section in Ghidra showing PUSH instructions for Hello World arguments followed by CALL to USER32.DLL::MessageBoxA, with the decompiled MessageBoxA call visible in the Decompiler panel on the right](task4-14.png)

The decompiler translates the argument pushes into a clean `MessageBoxA((HWND)0x0, "Hello World", "Hello World", 0)` call, confirming the binary simply displays a popup.

---

### Task 4 Questions

**Q: How many function calls are present in the Exports section?**

![Symbol Tree Exports section expanded showing one entry: the entry function](task4-15.png)

```
1
```

**Q: What is the only API call found in the User32.dll under the Imports section?**

![Symbol Tree Imports section with USER32.DLL expanded showing MessageBoxA as the only child entry](task4-16.png)

```
MessageBoxA
```

**Q: How many times can the "Hello World" string be found with the Search for Strings utility?**

![String Search window filtered for "Hello World" returning exactly 1 result](task4-17.png)

```
1
```

**Q: What is the virtual address of the CALL function that displays "Hello World" in a messagebox?**

![Disassembly showing CALL instruction at virtual address 004073d7 pointing to USER32.DLL::MessageBoxA with the Hello World string arguments visible above](task4-18.png)

```
004073d7
```

---

## Task 5 — Identifying C Code Constructs in Assembly

Rather than reading every instruction, experienced analysts look for **structural patterns** in assembly — loop signatures, conditional branches, function prologues — to understand logic at a higher level quickly.

All sample programs from the `Code_Constructs` folder are imported into the Ghidra project:

![Ghidra project showing all 6 files loaded: Benign.exe, for-loop.exe, func.exe, Hello_World.exe, if-else.exe, while-loop.exe](task5-01.png)

---

### Hello World (Console)

`Hello_World.exe` pushes `"HELLO WORLD!!\n"` onto the stack before calling the print function. The decompiler translates this instantly:

![Hello_World.exe in Ghidra showing PUSH s_HELLO_WORLD!! and CALL FUN_00401010 in the Listing panel, with the decompiled FUN_00401010("HELLO WORLD!!\n") call visible in the Decompiler panel](task5-02.png)

---

### For Loop

`for-loop.exe` shows the typical loop assembly pattern: initialize a counter, compare against a limit, perform work, increment, conditional jump back.

![for-loop.exe disassembly showing counter initialization, _puts call for THM_IS_Fun_to_Learn, ADD increment, CMP against 0xa, and JLE instruction jumping back to the loop start. Decompiled C on the right shows a for loop running from local_14 = 0 to local_14 < 0xb](task5-03.png)

💡 **Tip:** The `CMP` + conditional `JMP` pair is the assembly signature of any loop or branch. A backwards jump (`JLE`, `JNZ`, `JMP` to a lower address) means you're inside a loop; a forwards jump means a branch.

---

### While Loop

`while-loop.exe` main function loaded in Ghidra. The Symbol Tree shows `_main` selected and the decompiler shows the loop structure on the right:

![while-loop.exe main function in Ghidra with _main selected in Symbol Tree and decompiled C showing a for loop structure with _puts printing _ITs_Fun_to_Learn_at_THM_](task5-04.png)

Examining the full assembly reveals the do-while structure — `iVarl` is initialized to `4` and decremented by 1 each iteration until it reaches `0`:

![while-loop.exe detailed assembly view showing iVarl set to 4, the do-while loop body pushing _ITs_Fun_to_Learn_at_THM_\n and calling FUN_00401010, the SUB ESI,0x1 decrement, JNZ back to loop start, and the final _puts call for That's the end of while loop](task5-05.png)

🔴 **Malware relevance:** Loops are commonly found in malware for: retrying C2 connections, iterating over files during exfiltration, decryption routines, and anti-debug timing checks.

---

### If-Else

`if-else.exe` loaded in Ghidra with the decompiled pseudo-C visible, showing the program's string and conditional structure:

![if-else.exe in Ghidra Code Browser with _main selected in Symbol Tree and the decompiled C panel showing _puts("This program demonstrates if-else statement") call](task5-07.png)

---

### Task 5 Questions

**Q: What value gets printed by the while loop in the while-loop.exe program?**

*(Visible in both the listing as `s__ITs_Fun_to_Learn_at_THM__00402128` and the decompiler as the argument to `FUN_00401010`)*

```
_ITs_Fun_to_Learn_at_THM_
```

**Q: How many times will the while loop run until the condition is met?**

*(`iVarl` is initialized to `4` and decremented by 1 per iteration; the loop exits when `iVarl != 0` evaluates false, i.e. after 4 iterations)*

```
4
```

**Q: Examine the while-loop.exe in Ghidra. What is the virtual address of the instruction that CALLS to print out the sentence "That's the end of while loop .."?**

![while-loop.exe listing view showing the CALL _puts instruction at address 00401543 for the end-of-loop message, with the status bar at the bottom confirming address 00401543](task5-06.png)

```
00401543
```

**Q: In the if-else.exe program, examine the strings and complete the sentence "This program demonstrates..........."**

```
this program demonstrates if-else statement
```

**Q: What is the virtual address of the CALL to the main function in the if-else.exe program?**

![if-else.exe listing view showing the CALL __main instruction at virtual address 00401509, with the status bar at the bottom confirming 00401509](task5-08.png)

```
00401509
```

---

## Task 6 — An Overview of Windows API Calls

Windows APIs are the interface between user-mode code and the OS. Understanding which APIs malware commonly calls — and why — makes import table analysis during basic static analysis far more actionable.

### CreateProcess API

`CreateProcessA` creates a new process and its primary thread. Its full C++ signature from MSDN:

![MSDN documentation page showing the full CreateProcessA function signature with all parameters listed including lpApplicationName, lpCommandLine, dwCreationFlags, lpStartupInfo, and lpProcessInformation](task6-01.png)

The `dwCreationFlags` parameter controls how the new process starts. The flag critical to injection techniques:

| Flag | Value | Meaning |
|------|-------|---------|
| `CREATE_SUSPENDED` | `0x00000004` | Creates the process with its primary thread in a suspended state — does not execute until `ResumeThread` is called |

🔴 **Malware relevance:** `CREATE_SUSPENDED` is the first step of **process hollowing**. By launching a legitimate process in a suspended state, the attacker can manipulate its memory before a single instruction executes. From the OS perspective, the process looks completely normal.

**Q: When a process is created in suspended state, which hexadecimal value is assigned to the dwCreationFlags parameter?**

```
0x00000004
```

---

## Task 7 — Common APIs Used by Malware

A reference map of Windows APIs commonly found in malware imports. Seeing these during basic static analysis tells you what the malware is *capable of* before opening a disassembler.

| Malware Category | Key APIs |
|-----------------|----------|
| Keylogger | `SetWindowsHookEx`, `GetAsyncKeyState`, `GetKeyboardState`, `GetKeyNameText` |
| Downloader | `URLDownloadToFile`, `WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest` |
| C2 Communication | `InternetOpen`, `InternetOpenUrl`, `HttpOpenRequest`, `HttpSendRequest` |
| Data Exfiltration | `InternetReadFile`, `FtpPutFile`, `CreateFile`, `WriteFile`, `GetClipboardData` |
| Dropper | `CreateProcess`, `VirtualAlloc`, `WriteProcessMemory` |
| API Hooking | `GetProcAddress`, `LoadLibrary`, `SetWindowsHookEx` |
| Anti-Debug / VM Detection | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `GetTickCount`, `GetSystemMetrics` |

🔴 **Malware relevance:** Seeing `WriteProcessMemory` + `VirtualAllocEx` + `CreateProcessA` together in an import table is a strong indicator of **process injection or hollowing** — even before opening a disassembler. Import analysis is not just a box-ticking exercise; it directly shapes what you look for in Ghidra.

💡 **Tip:** [malapi.io](https://malapi.io) maps Windows APIs to the malware families that use them — useful as a quick reference during triage.

---

## Task 8 — Process Hollowing: Overview

**Process hollowing** (MITRE ATT&CK: [T1055.012](https://attack.mitre.org/techniques/T1055/012/)) is a code injection technique where malware creates a legitimate process, empties its memory, and replaces it with malicious code. The injected code then runs inside the context of the legitimate process.

### The Hollowing API Chain

| Step | API | Purpose |
|------|-----|---------|
| 1 | `CreateProcessA` | Spawn a legitimate process (e.g., `iexplore.exe`) in `CREATE_SUSPENDED` state |
| 2 | `NtUnmapViewOfSection` | Unmap the legitimate process's image from its own memory |
| 3 | `VirtualAllocEx` | Allocate new memory in the hollowed process |
| 4 | `WriteProcessMemory` | Write the malicious binary into the allocated memory |
| 5 | `SetThreadContext` | Redirect the suspended thread's entry point to the malicious code |
| 6 | `ResumeThread` | Resume the process — it now executes the injected code |

🔴 **Malware relevance:** From the OS and most security tools' perspective, the malicious code runs inside a recognized, legitimate process. Process-based detection sees `iexplore.exe` — not malware. This is precisely why static analysis of imports and disassembly is needed to expose what's really happening.

**Q: Which API is used to write malicious code to the allocated memory during process hollowing?**

```
WriteProcessMemory()
```

---

## Task 9 — Analyzing Process Hollowing

The target sample is `Benign.exe` located on the Desktop. Despite the name, this binary implements process hollowing — injecting `evil.exe` into a suspended `iexplore.exe` process.

Our objectives:
- Examine API calls for suspicious patterns
- Look at suspicious strings
- Find interesting / malicious functions
- Examine disassembled and decompiled code

---

### Load the Sample

Import `Benign.exe` into Ghidra. The Import Results Summary gives immediate context:

![Benign.exe Import Results Summary showing Executable MD5 e60a461b80467a4b1187ae2081f8ca24, PDB file simplehollow.pdb, x86 LE 32-bit PE, compiled with visualstudio](task9-01.png)

💡 **Tip:** The PDB filename `simplehollow.pdb` leaks the original Visual Studio project name — confirming this is a process hollowing sample before a single line of code is read. PDB filenames are a common OPSEC failure in malware developed in Visual Studio.

### Analyze

Let Ghidra analyze the sample:

![Ghidra analyze prompt for Benign.exe asking whether to analyze it now](task9-02.png)

---

### CreateProcess

In process hollowing, the malware creates a victim process in a suspended state. To confirm, search for `CreateProcessA` in the Symbol Tree, then right-click → **Show References to**:

![Right-click context menu on CreateProcessA in the Symbol Tree showing the Show References to option highlighted](task9-03.png)

![References to CreateProcessA window showing 2 locations: 0040108f listed as COMPUTED_CALL and 00403034 listed as DATA](task9-04.png)

Clicking the first reference (`0040108f`) jumps to the call site. The disassembly shows all parameters being pushed onto the stack in reverse order before the `CALL`, and the decompiler on the right shows the full function call in pseudo-C:

![Disassembly at 0040108f showing PUSH instructions for all CreateProcessA parameters including 0x4 for dwCreationFlags and the iexplore.exe path string, followed by CALL to KERNEL32.DLL::CreateProcessA, with decompiled C on the right showing CreateProcessA called with iexplore.exe and dwCreationFlags = 0x4](task9-05.png)

The value `0x4` pushed for `dwCreationFlags` is `CREATE_SUSPENDED` — the victim process is created in a suspended state before any of its code runs:

![MSDN documentation showing CREATE_SUSPENDED flag with value 0x00000004 and description that the primary thread is created in suspended state and does not run until ResumeThread is called](task9-06.png)

---

### Graph View

Clicking **Display Function Graph** in the toolbar reveals the conditional branches following the `CreateProcessA` call:

![Function Graph for Benign.exe showing the main code block with CreateProcessA call, a red arrow leading to failure block 1 at 00401099 containing GetLastError and error print, and a green arrow leading to success block 2 at 004010c2](task9-07.png)

| Branch | Condition | Target Block |
|--------|-----------|-------------|
| 🔴 Red (failure) | `CreateProcessA` returns 0 — victim process not created | `00401099` |
| 🟢 Green (success) | Victim process created in suspended state | `004010c2` |

---

### Open Suspicious File

`CreateFileA` is used to create or open an existing file. Searching for it in the Symbol Tree and navigating to its reference reveals what file the malware is opening:

![Disassembly at 004010f0 showing PUSH parameters for CreateFileA including the evil.exe path string and 0x80000000 access flag, followed by CALL to KERNEL32.DLL::CreateFileA, with decompiled C on the right showing CreateFileA opening C:\Users\THM-Attacker\Desktop\Injectors\evil.exe](task9-08.png)

The decompiler confirms `CreateFileA` is opening `evil.exe` — the malicious binary that will replace `iexplore.exe`'s memory.

---

### Hollow the Process

Malware uses `ZwUnmapViewOfSection` or `NtUnmapViewOfSection` to unmap the target process's memory. Searching the Symbol Tree confirms `NtUnmapViewOfSection` is present under NTDLL.DLL:

![Symbol Tree showing NtUnmapViewOfSection under NTDLL.DLL imports with the disassembly showing PUSH arguments and CALL to NTDLL.DLL::NtUnmapViewOfSection at address 0040123f, and decompiled C on the right showing iVar4 = NtUnmapViewOfSection(lpProcessInformation->hProcess, local_10)](task9-09.png)

`NtUnmapViewOfSection` takes exactly two arguments — the process handle and the base address to unmap — stripping the legitimate `iexplore.exe` image from its own memory.

---

### Allocate Memory

With the process now hollowed, the malware allocates new memory to hold the replacement image using `VirtualAllocEx`. Arguments include the process handle, target address, size, allocation type, and memory protection flags:

![Disassembly showing multiple PUSH instructions for VirtualAllocEx parameters followed by CALL to KERNEL32.DLL::VirtualAllocEx at address 004012d0, with decompiled C on the right showing pvVar5 = VirtualAllocEx(lpProcessInformation->hProcess, local_10, dwSize, 0x3000, 0x40)](task9-10.png)

---

### Write Down the Memory

Once memory is allocated, `WriteProcessMemory` writes the malicious binary into the hollowed process. Locating this function and analyzing the code:

![Disassembly at 00401394 showing PUSH EAX, PUSH dword ptr [EBX], CALL to KERNEL32.DLL::WriteProcessMemory, with decompiled C on the right showing WriteProcessMemory writing each PE section of evil.exe one by one in a do-while loop](task9-11.png)

There are three references to `WriteProcessMemory` — but the last one references code in Kernel32 DLL itself and can be ignored. The two active calls in `.text` copy different PE sections of `evil.exe` into the hollowed process one by one.

---

### Resume Thread

Once all sections are written, the malware gets hold of the thread using `SetThreadContext`, then resumes it using `ResumeThread` to execute the injected code:

![Disassembly showing CALL to KERNEL32.DLL::SetThreadContext at 00401413 and CALL to KERNEL32.DLL::ResumeThread at 00401447, with decompiled C on the right showing SetThreadContext at line 130 and ResumeThread at line 136](task9-12.png)

The hollowing chain is complete. `iexplore.exe` resumes — but it is now executing `evil.exe`.

---

### Task 9 Questions

**Q: What is the MD5 hash of the benign.exe sample?**

![Benign.exe Import Results Summary in Ghidra project manager showing Executable MD5: e60a461b80467a4b1187ae2081f8ca24](task9-13.png)

```
e60a461b80467a4b1187ae2081f8ca24
```

**Q: How many API calls are returned if we search for the term 'Create' in the Symbol Tree section?**

![Symbol Tree filtered by "Create" showing CreateFileA and CreateProcessA under KERNEL32.DLL — exactly 2 results](task9-14.png)

```
2
```

**Q: What is the first virtual address where the CreateProcessA function is called?**

![References to CreateProcessA window with 0040108f highlighted as the first COMPUTED_CALL entry](task9-15.png)

```
0040108f
```

**Q: Which process is being created in suspended state by using the CreateProcessA API call?**

![Disassembly at 0040108f with decompiled C on the right showing CreateProcessA called with C:\Program Files (x86)\Internet Explorer\iexplore.exe as the target and dwCreationFlags = 0x4](task9-16.png)

```
iexplore.exe
```

**Q: What is the first virtual address where the CreateFileA function is called?**

![References to CreateFileA window showing 2 locations with 004010f0 highlighted as the first COMPUTED_CALL entry](task9-17.png)

```
004010f0
```

**Q: What is the suspicious process being injected into the victim process?**

![Disassembly at 004010f0 showing CreateFileA call with decompiled C on the right showing hFile = CreateFileA("C:\Users\THM-Attacker\Desktop\Injectors\evil.exe", ...)](task9-18.png)

```
evil.exe
```

**Q: Based on the Function Graph, what is the virtual address of the code block that will be executed if the program doesn't find the suspicious process?**

![Function Graph showing the failure branch after CreateFileA conditional — red arrow leading to the block starting at 00401101 which calls GetLastError and prints an error message](task9-19.png)

```
00401101
```

**Q: Which API call is found in the import functions used to unmap the process's memory?**

![Symbol Tree filtered by "unm" showing NtUnmapViewOfSection under NTDLL.DLL in the Imports section](task9-20.png)

```
NtUnmapViewOfSection
```

**Q: How many calls to the WriteProcessMemory function are found in the code? (.text section)**

![References to WriteProcessMemory window showing 3 locations: 00403004 as DATA (IAT pointer), 00401394 as COMPUTED_CALL, and 0040133f as COMPUTED_CALL](task9-21.png)

*(3 total references — 1 is a `DATA` entry in the IAT, 2 are `COMPUTED_CALL` entries in `.text`)*

```
2
```

**Q: What is the full path of the suspicious process shown in the strings?**

![String Search in Benign.exe filtered by "c:" showing three path strings with C:\Users\THM-Attacker\Desktop\Injectors\evil.exe highlighted and visible in the Preview bar at the bottom](task9-22.png)

```
C:\Users\THM-Attacker\Desktop\Injectors\evil.exe
```

---

## Task 10 — Conclusion

This room walked through the full advanced static analysis workflow: setting up Ghidra, recognizing C constructs in assembly, understanding malware API categories, and performing a complete end-to-end analysis of a process hollowing sample.

The next step in the SOC Level 2 path is **Advanced Dynamic Analysis** — observing the same techniques at runtime.

---

## Key Takeaways

- **Advanced static analysis** never executes the malware — it reverses compiled code to understand behavior from disassembly and decompiled pseudo-C alone
- **Ghidra's analysis workflow:** Import → Analyze → Symbol Tree (Imports/Exports) → String Search → Listing + Decompiler → Function Graph
- **C constructs in assembly** follow consistent patterns: loops use `CMP` + conditional backward `JMP`; if-else uses a forward conditional `JMP`; functions open with the `PUSH EBP / MOV EBP, ESP` prologue
- **The process hollowing API chain in order:** `CreateProcessA (0x4)` → `NtUnmapViewOfSection` → `VirtualAllocEx` → `WriteProcessMemory` → `SetThreadContext` → `ResumeThread`
- **`CREATE_SUSPENDED` (`0x00000004`)** in `dwCreationFlags` is the key indicator that a process is being set up for injection — spotting this in imports flags the binary before disassembly even begins
- **`NtUnmapViewOfSection`** is from `NTDLL.DLL`, not `KERNEL32.DLL` — it strips the legitimate image from the victim process before the malicious one is written in
- **Import table analysis is not just preliminary** — `WriteProcessMemory` + `VirtualAllocEx` + `NtUnmapViewOfSection` together in imports is sufficient to classify a sample as a process injector before reading a single instruction
- **PDB filenames** in the import summary can expose the original project name — `simplehollow.pdb` gave away this sample's purpose instantly, a common OPSEC failure in malware developed in Visual Studio

---

*Write-up by [OPT4RUN](https://tryhackme.com/p/OPT4RUN)*