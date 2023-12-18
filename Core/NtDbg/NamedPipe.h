#pragma once

#include "pch.h"

#include <iostream>
#include <queue>
#include <mutex>
#include <thread>

#define LP_TEXT_STRING(s) ((LPTSTR)TEXT(s)) // Formats a string literal so that it can be sent to the pipe server.

class Pipe
{
public:
	BOOL bPipeOpen;

	Pipe(LPTSTR lpszPipename);
	~Pipe();
	void SendMessage(LPTSTR lpvMessage);
private:
	HANDLE hPipe;
	LPTSTR lpszPipename;
	std::queue<LPTSTR> m_MessageQueue;
	std::mutex queueMutex;

	DWORD ProcessMessages();
	BOOL InitPipe();
};