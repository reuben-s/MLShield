#include "ProcessManager.h"

void ProcessManager::ProcessCreate(ULONG pid)
{
	m_Processes.insert({ pid, std::make_unique<Process>(pid) });
}