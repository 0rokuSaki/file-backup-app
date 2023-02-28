/*****************************************************************//**
 * \file   main.cpp
 * \brief  Main function for the client.
 * Please read the README.md file for more information about this program.
 * Repository link: https://github.com/0rokuSaki/file-backup-app
 * 
 * \author aaron
 * \date   February 2023
 *********************************************************************/

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