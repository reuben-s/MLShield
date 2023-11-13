#pragma once

#include "pch.h"

#include <iostream>

#define LP_TEXT_STRING(s) ((LPTSTR)TEXT(s)) // Formats a string literal so that it can be sent to the pipe server.

class Pipe
{
public:
	BOOL bPipeOpen;

	Pipe(LPTSTR lpszPipename);
	~Pipe();
	BOOL SendMessage(LPTSTR lpvMessage);
private:
	HANDLE hPipe;
	LPTSTR lpszPipename;

	BOOL InitPipe();
};