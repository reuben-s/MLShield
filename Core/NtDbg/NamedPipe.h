#pragma once

#include "pch.h"

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