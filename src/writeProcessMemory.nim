import winim
import os, osproc

proc transformData*[I, T](data: array[I, T]): array[I, T] =
    var result: array[len(data), T] = data
    when defined(USE_BITSWITCH):
        for i in 0..<len(data):
            result[i] = T(ord(data[i]) xor ord(0b10101010))
    when defined(USE_XOR):
        let xorKey = 0x5A
        for i in 0..<len(data):
            result[i] = T(ord(data[i]) xor xorKey)
    return result

proc writeMemory*[I, T](pHandle: HANDLE, targetAddr: LPVOID, data: array[I, T]): bool =
    var bytesWritten: SIZE_T
    let transformedData = transformData(data)
    let wSuccess = WriteProcessMemory(
        pHandle,
        targetAddr,
        unsafeAddr transformedData,
        cast[SIZE_T](transformedData.len),
        addr bytesWritten
    )
    return bool(wSuccess)