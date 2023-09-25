// https://github.com/zodiacon/windowskernelprogrammingbook2e/blob/master/Chapter09/SysMon/FastMutex.cpp

#include "pch.h"
#include "FastMutex.h"

void FastMutex::Init() 
{
	ExInitializeFastMutex(&m_mutex);
}

void FastMutex::Lock() 
{
	ExAcquireFastMutex(&m_mutex);
}

void FastMutex::Unlock() 
{
	ExReleaseFastMutex(&m_mutex);
}