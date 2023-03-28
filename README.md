# nimjector
A dive into shellcode injection and EDR evasion techniques in nim (but with a punny name)

## Planned Folder Structure
```
root/
|__src/
   |__main.nim              # Entry point of the application
   |__loader/
      |__loader.nim         # Implementation of the shell loader
      |__injector.nim       # Implementation of the shell injector
   |__sandbox/
      |__sandbox.nim        # Implementation of sandbox escaping
   |__hashing/
      |__hashing.nim        # Implementation of Windows API hashing
   |__injection/
      |__createremotethread.nim # Implementation of CreateRemoteThread injection technique
      |__fibers.nim             # Implementation of Fibers injection technique
      |__createprocess.nim      # Implementation of CreateProcess injection technique
      |__earlybirdapc.nim       # Implementation of EarlyBirdAPC injection technique
      |__uuidfromstring.nim     # Implementation of UuidFromString injection technique
   |__ntdllunhooking/
      |__unhooking.nim      # Implementation of NTDLL unhooking techniques
   |__evading/
      |__amsi.nim           # Implementation of AMSI evasion techniques
      |__etw.nim            # Implementation of ETW evasion techniques
      |__shellcodeflip.nim  # Implementation of shellcode byte flip evasion technique
      |__masquerading.nim   # Implementation of masquerading processes in userland via PEB evasion technique
   |__signing/
      |__signing.nim        # Implementation of auto exe signing feature
|__tests/
   |__loader/
      |__loader_tests.nim   # Unit tests for the loader module
      |__injector_tests.nim # Unit tests for the injector module
   |__sandbox/
      |__sandbox_tests.nim  # Unit tests for the sandbox module
   |__hashing/
      |__hashing_tests.nim  # Unit tests for the hashing module
   |__injection/
      |__createremotethread_tests.nim # Unit tests for CreateRemoteThread injection technique
      |__fibers_tests.nim             # Unit tests for Fibers injection technique
      |__createprocess_tests.nim      # Unit tests for CreateProcess injection technique
      |__earlybirdapc_tests.nim       # Unit tests for EarlyBirdAPC injection technique
      |__uuidfromstring_tests.nim     # Unit tests for UuidFromString injection technique
   |__ntdllunhooking/
      |__unhooking_tests.nim # Unit tests for the ntdll unhooking module
   |__evading/
      |__amsi_tests.nim      # Unit tests for AMSI evasion techniques
      |__etw_tests.nim       # Unit tests for ETW evasion techniques
      |__shellcodeflip_tests.nim # Unit tests for shellcode byte flip evasion technique
      |__masquerading_tests.nim  # Unit tests for masquerading processes in userland via PEB evasion technique
   |__signing/
      |__signing_tests.nim   # Unit tests for the auto exe signing module
```