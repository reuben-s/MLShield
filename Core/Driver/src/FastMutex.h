// https://github.com/zodiacon/windowskernelprogrammingbook2e/blob/master/Chapter09/SysMon/FastMutex.h

#pragma once

#include "pch.h"

class FastMutex 
{
public:
	void Init();

	void Lock();
	void Unlock();

private:
	FAST_MUTEX m_mutex;
};