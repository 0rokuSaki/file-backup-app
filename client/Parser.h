#pragma once
#include <sstream>
#include <string>
#include <vector>

class Parser
{
public:
    /* API Methods */
    bool parseTransferInfo(std::stringstream& errMsg);
    bool parseMeInfo(std::stringstream& errMsg);
    std::string getHostAddress();
    std::string getHostPort();
    std::string getClientName();
    std::string getFilePath();
    std::string getFileName();
    std::string getPrivateKeyBase64();
    std::vector<uint8_t> getClientID();

private:
    /* Instance variables */
    std::string _hostAddress;
    std::string _hostPort;
    std::string _clientName;
    std::string _filePath;
    std::string _fileName;
    std::string _privateKeyBase64;
    std::vector<uint8_t> _clientID;
};

