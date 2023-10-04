#pragma once

#include <unordered_map>
#include <memory>
#include "Process.h"

class ProcessManager
{
public:
	void ProcessCreate(ULONG pid);


private:
	std::unordered_map<ULONG, std::unique_ptr<Process>> m_Processes;
};