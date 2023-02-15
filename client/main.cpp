#include "ClientLogic.h"

int main(int argc, char** argv)
{
    const std::string exePath(argv[0]);
    ClientLogic clientLogic(exePath.substr(0, exePath.find_last_of("\\")));
    std::cout << "\n============================================================\n" << std::endl;
    if (!clientLogic.initialize())
    {
        std::cerr << "Fatal error: failed to initialize ClientLogic. Aborting..." << std::endl;
        return -1;
    }
    std::cout << "\n============================================================\n" << std::endl;
    return 0;
}