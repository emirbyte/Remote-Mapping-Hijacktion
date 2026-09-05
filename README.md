# Remote Mapping Injection PoC

In this project, I've developed a simple Proof-of-Concept of the popular Malware Development / Process Injection technique — **Remote Mapping Injection** — and documented what is going on during the process of "Remote Mapping Injection" technique, what is different about this specific technique and how it is useful for us.

## What is Remote Mapping Injection?

Remote Mapping Injection is an intermediate Process Injection method that allows us to avoid using functions like `VirtualAllocEx` (used to allocate memory over in remote processes), `WriteProcessMemory` (used to write to remote memory), and `VirtualProtectEx` (used to change permissions of the remote memory). While avoiding the functions above, we also avoid the usage of Private Memory pages (blocks of virtual memory for a single process - when used with ReadExecute/ReadWriteExecute permissions, it is more suspicious than Mapped memory), which makes us more versatile and silent in the system. Mapped Memory can be used by multiple processes at once, but unlike Private Memory pages, there's a ceiling to modifying permissions — we will come to this later. 

The reason for using mapped memory for our shellcodes, which require executable memory, is because we will need RWX (Read-Write-Execute) or, with simple maneuvers, RX (Read-Execute). Having RWX permissions on private memory creates a huge Red-Flag for security solutions, EDRs, and AVs. A private memory page with RWX permissions and no relations to the disk is a huge red flag, but Mapped memory, which has a direct relation to a section/file object, is more legitimate. By "more legitimate," I don't mean that it's completely legitimate, since it still violates a very simple and important security rule: memory shouldn't be writable and executable at the same time. Still, it is more legitimate than a private memory. We can work around being R W X at the same time by using `VirtualProtectEx` (I will come to this later as well).

### Advantages
* **Evasion Potential** — Evading traditional Injection APIs.
* **Versatile** — No need to allocate memory in the remote thread, mapped memory is shared.
* **Legitimacy** — We are not using private memory pages (anonymous memory). It is more legitimate when it's backed up by the file/section-backed method.

### Disadvantages
* **Increased API Footprint** — More steps = More endpoints for EDR to catch on and intercept.
* **Single Point of Failure** — Single Shared mapped memory; if it's **Unmapped**, the handle is gone.

---

## How It Works

This Proof-of-Concept uses several well-known techniques that include **AES-256 Encryption**, **Local Shellcode Decryption**, **Remote Mapping Injection**, and **Remote Thread Hijacking**.

Let's go step by step to dive deeper into my proof of concept.

### Step 1 - Encryption
The program comes with an AES-256 Encrypted Shellcode that will be decrypted locally in memory before being injected remotely. This is a simple but effective evasion step to stay under the radar while starting up. **Bcrypt API** is used in this step.

### Step 2 - Mapping
At this stage, the **Remote Mapping Injection** officially runs.

1. Firstly, `CreateFileMappingW` is called with its return value being a `HANDLE`. This function is supposed to return us a File Section Object that can be used System-Wide to create mapped memory sections. It takes several arguments like the size and the file. The file handle argument can be left empty by entering `INVALID_HANDLE_VALUE` instead. This is more reliable for us since we can avoid being reliant on a disk file.
2. The object now must be mapped locally to our process with the `MapViewOfFile` API. This will be important later on.
3. The object now can be mapped in any running process at that time by using the `MapViewOfFile2` API.

`MapViewOfFile2` API allows us to map the file object *remotely* to other processes. But we need to pass the API a Process Handle — this handle **MUST** contain `PROCESS_VM_OPERATION` permission. The API also asks us for Memory Permissions for the Mapped Section. As I've pointed out before, any memory section with "RWX" permissions is a huge red flag for any security solution and should be avoided. We work around this by giving the `MapViewOfFile2` API `PAGE_READWRITE` argument for the protection (This will be changed using `VirtualProtectEx`, an API that allows us to change the memory page permissions, after we write the payload to the mapped memory).

> **Where it comes to use:**
> Here, we finally achieve our goal, which was to avoid allocating private remote memory. As you remember, we mapped the section both locally and remotely. We can think of this as a simple portal. The mapped page points to the same memory in both processes: local and remote. We do not need to write to the remote process or allocate memory there. We can now just write the payload bytes to our local mapped section, and it will be available in both processes just like that.

### Step 3 - Injection
For the last part, after the process of decrypting and mapping the payload to the remote process, we can finally move on to the Injection/Execution method I've used.

I've used a technique named **Remote Thread Hijacking** with the MITRE ID: [T1055.003](https://attack.mitre.org/techniques/T1055/003/). This technique will target the remote threads by firstly enumerating them via `CreateToolhelp32Snapshot` (System-wide Process/Thread/Module Snapshot) and finding the target process's threads. Afterwards, we will suspend the thread, change the thread's `RIP`/`EIP` (Next instruction pointer — think of it as a finger pointing to the next instruction) to our Mapped Memory Address containing our malicious shellcode bytes (It opens the calculator, so malicious!).

In the process of finding the target thread, I used an optional technique I discovered by thinking it out. By circling through the snapshot and finding the thread owned by the target process, we get the *Main Thread ID*, which might create problems when we change its `RIP` or suspend it. To work around this issue, I've added two simple checkpoints:

* **check1** -> When you find the main thread (the first thread owned by the target), make check1 `TRUE`.
* **check2** -> If only you were able to find a secondary thread owned by the target, make check2 `TRUE`.

In the end, if check2 isn't ticked, just use the main thread. But if it's ticked, use the secondary thread we found.

This way, we avoid using an unreliable thread that may cause the whole process to crash if we change its next instruction or suspend it. We use the `GetThreadContext`/`SetThreadContext` duo to get the thread struct, and after editing the object we got, we can set the object to the thread. Then we can finally resume the remote thread, hijacking it and making it a zombie for our intentions.

# Walkthrough of the process

<img width="1290" height="487" alt="locallymapped" src="https://github.com/user-attachments/assets/b6cca5d4-686b-4e9d-8659-fb116d5f63a7" />
<img width="1236" height="673" alt="mappedremotely" src="https://github.com/user-attachments/assets/23ec59ba-b17b-450d-baa4-c7e39f87163d" />
<img width="578" height="719" alt="remotemappingshared" src="https://github.com/user-attachments/assets/fb8aa6f7-b45c-429f-8023-890320b16d50" />
<img width="1124" height="580" alt="suspendingthread" src="https://github.com/user-attachments/assets/8e2f76b2-1bd5-4c96-812b-01aa6da87ef8" />
<img width="1165" height="301" alt="originalrip" src="https://github.com/user-attachments/assets/98ac5af6-5d09-47e7-98b1-b8c1fb2d8309" />
<img width="1259" height="488" alt="hijackedrip" src="https://github.com/user-attachments/assets/4bfe9728-3ce4-4f7d-8f8a-fcf5de22aadf" />
<img width="1198" height="492" alt="pointsto" src="https://github.com/user-attachments/assets/92708757-21f5-4a08-bf2b-90905123448a" />


