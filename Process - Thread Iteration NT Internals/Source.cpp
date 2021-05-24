#include "gWin_ProcessEnumerator.h"

int main() {

	gWin::ProcessEnumerator procEnum;

	for (auto &process : procEnum.getProcesses()) {
		if (process.getName() == "Neuz.exe") {

			for (auto &thread : process.getThreads()) {
				auto modInfo = process.getAssociatedModule(&thread);

				std::cout << modInfo.name << "+" << std::hex << 
					thread.getStartAddress() - modInfo.base << std::endl;

				if (modInfo.name.find("GameGuard") != std::string::npos)
					SuspendThread(thread.getHandle().getRaw());

				if (modInfo.name.find("Neuz") != std::string::npos)
					if (thread.getWaitReason() == DelayExecution)
						SuspendThread(thread.getHandle().getRaw());
			}
		}
	}

	return 0;
}