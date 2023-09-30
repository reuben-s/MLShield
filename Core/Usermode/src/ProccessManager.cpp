#include "ProcessManager.h"

void ProcessManager::ProcessCreate(ULONG pid)
{
	std::shared_ptr<Process> newProcess = std::make_shared<Process>(pid);
	m_Processes.insert({ pid, newProcess });
}