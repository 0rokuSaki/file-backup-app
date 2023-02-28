#include "ClientLogic.h"

int main(int argc, char** argv)
{
    ClientLogic clientLogic;

    std::cout << "\n============================================================\n" << std::endl;

    if (!clientLogic.initialize())
    {
        std::cerr << "Fatal error: failed to initialize ClientLogic. Aborting..." << std::endl;
        return -1;
    }

    std::cout << "\n============================================================\n" << std::endl;

    if (!clientLogic.run())
    {
        std::cerr << "Fatal error: failure during runtime. Aborting..." << std::endl;
        return -1;
    }

    std::cout << "\n============================================================\n" << std::endl;

    return 0;
}