# iOS 9 Kernel Code Execution API

C++ source to modify or execute kernel memory by utilizing freed pointer. Created by analyzing ARM disassembly and Pangu's jailbreak.

## Usage
Originally designed for an entrypoint to modify kernel drivers running in memory.  
Changing the behavior of the modem, wireless card, or other hardware in the iPhone becomes possible with this code.  

With some modification, this can be used as a kernel dump tool.
The current version of this code prints out the ASLR slide and object address for the running kernel.

## Version Support
Currently 32-bit support for iOS 8, iOS 9.0.2 (Some modification may allow support for up to 9.2)

## Compiling
The necessary IOKit headers and dependencies have been included. Xcode must be installed to compile.
```bash
git clone https://github.com/Falconscript/ioskernpatchapi
cd ioskernpatchapi
./compile.sh
```

## Running
A compiled binary for the iPhone 5 on iOS 8.4 is included. This can be scp'd to your device and run in its terminal to produce these results:
```c
[*] iOS kernpatchapi
[D] Starting (exec_arch=32-bit) (proc_arch=32-bit) (endian=little) sizeof(ull)=8 sizeof(uint64_t)=8
[D] Initializing heapsprayer
[D] Opening services
[*] handleReport kern Result: [0xb94973c0 aka -1186368576 - (null)]
[*] handleReport kern Result: [0xb94973c0 aka -1186368576 - (null)]
[*] handleReportAsync kernRet: [0x8f7fbe84 aka -1887453564 - (null)]
[*] kSLIDE - [0xf0c00000]  OBJ_ADDR - [0xb94973c0]

[!] FINISHED.
```

## Adding on
Determine the offsets for the kernel static for OSMetaClass and ROP gadgets for your specific iOS device and version combination.

With those primitive functions prepared, the running kernel drivers should be at your mercy.  
A bit of work is planned to make this easier soon.

## Caveats
The nature of the bug used to gain kernel memory access isn't 100% reliable. The compiled executable may crash the phone causing reboots.  
These reboots are safe, but sometimes annoying. If using for a production tweak, do as Pangu does: Run the code near the start of the iPhone boot so a crash isn't as noticeable.  
Make sure your code works before hooking into the book to prevent boot loops.  

## Credits
Thanks to all the top jailbreakers for their unbelievable talent and dedication in opening iOS to the public.  
Special thanks to qwertyoruiop for fantastic suggestions.  
Thanks to Pangu for creating the original iOS 9 jailbreak and writeup.


Project home page:  
http://x64projects.tk/
