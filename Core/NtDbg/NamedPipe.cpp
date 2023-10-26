#include "pch.h"
#include "NamedPipe.h"
#include <iostream>

Pipe::Pipe(LPTSTR lpszPipename)
{
	this->lpszPipename = lpszPipename;
	this->bPipeOpen = this->InitPipe();
}

BOOL Pipe::InitPipe()
{
	while (true)
	{
		this->hPipe = CreateFile(
			this->lpszPipename,   // pipe name 
			GENERIC_READ |        // read and write access 
			GENERIC_WRITE,
			0,					  // no sharing 
			NULL,                 // default security attributes
			OPEN_EXISTING,        // opens existing pipe 
			0,                    // default attributes 
			NULL			      // no template file
		);

		if (hPipe != INVALID_HANDLE_VALUE)
			break;

		if (GetLastError() != ERROR_PIPE_BUSY)
		{
			std::cout << "Could not open pipe. GLE=" << GetLastError() << std::endl;
			return FALSE;
		}

		// All pipe instances are busy, so wait for 20 seconds. 

		if (!WaitNamedPipe(lpszPipename, 20000))
		{
			std::cout << "Could not open pipe: 20 second wait timed out." << std::endl;
			return FALSE;
		}
	}

	DWORD dwMode = PIPE_READMODE_MESSAGE;
	BOOL fSuccess = SetNamedPipeHandleState(
		this->hPipe,    // pipe handle 
		&dwMode,		// new pipe mode 
		NULL,			// don't set maximum bytes 
		NULL			// don't set maximum time
	);
	if (!fSuccess)
	{
		std::cout << "SetNamedPipeHandleState failed. GLE=" << GetLastError() << std::endl;
		return FALSE;
	}

	return fSuccess;
}

BOOL Pipe::SendMessage(LPTSTR lpvMessage)
{
	if (!this->bPipeOpen)
		return FALSE;

	BOOL cbToWrite = (lstrlen(lpvMessage) + 1) * sizeof(TCHAR);

	DWORD cbWritten = 0;
	BOOL fSuccess = WriteFile(
		hPipe,                  // pipe handle 
		lpvMessage,             // message 
		cbToWrite,              // message length 
		&cbWritten,             // bytes written 
		NULL);                  // not overlapped 

	if (!fSuccess)
	{
		std::cout << "WriteFile to pipe failed GLE=" << GetLastError() << std::endl;
		return FALSE;
	}

	return fSuccess;
}

Pipe::~Pipe()
{
	CloseHandle(this->hPipe);
}