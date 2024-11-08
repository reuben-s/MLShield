from .bindings import (
    ReadFile,
    WriteFile,
    DWORD,
    GetLastError,
    ERROR_BROKEN_PIPE,
    ERROR_PIPE_LISTENING,
    GetNamedPipeClientProcessId
)

from .exceptions import (
    CLIENT_DISCONNECTED,
    READFILE_FAILED,
    WRITEFILE_FAILED,
    ERROR_PIPE_LISTENING
)

from ctypes import (
    create_unicode_buffer,
    sizeof,
    byref
)

from .settings import BUFSIZE

def WriteToNamedPipe(pipe, message):
    unicode_buffer = create_unicode_buffer(BUFSIZE)
    unicode_buffer.value = message
    bytes_written = DWORD(0)

    success = WriteFile(
        pipe,
        unicode_buffer,
        sizeof(unicode_buffer),
        byref(bytes_written)
    )

    if (not success) or (sizeof(unicode_buffer) != bytes_written.value):
        if GetLastError() == ERROR_BROKEN_PIPE:
            raise CLIENT_DISCONNECTED("Client Disconnected")
        else:
            raise WRITEFILE_FAILED(f"WriteFile failed GLE={GetLastError()}")

    return success

def ReadFromNamedPipe(pipe):
    unicode_buffer = create_unicode_buffer(BUFSIZE)
    bytes_read = DWORD(0)

    success = ReadFile(
        pipe,
        unicode_buffer,
        sizeof(unicode_buffer),
        byref(bytes_read)
    )

    if (not success) or (bytes_read == 0):
        err = GetLastError()
        if err == ERROR_BROKEN_PIPE:
            raise CLIENT_DISCONNECTED("Client Disconnected")
        elif err == ERROR_PIPE_LISTENING:
            raise ERROR_PIPE_LISTENING("No process on other end of pipe")
        else:
            raise READFILE_FAILED(f"ReadFile failed GLE={GetLastError()}")
    
    return unicode_buffer.value

def GetClientPID(pipe):
    PID = DWORD(0)
    success = GetNamedPipeClientProcessId(pipe, byref(PID))
    if success:
        return PID.value
    return False