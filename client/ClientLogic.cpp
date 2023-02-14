#include "ClientLogic.h"
#include "Utilities.h"

#include "Base64Wrapper.h"
#include "RSAWrapper.h"

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

ClientLogic::ClientLogic(const std::string& rootPath) : _rootPath(rootPath)
{
}


void ClientLogic::run()
{
    boost::asio::io_context io_context;
    tcp::socket socket(io_context);
    tcp::resolver resolver(io_context);
}

bool ClientLogic::parseTransferInfo()
{
    std::ifstream transferInfoFile(_rootPath + "\\transfer.info");

    /* Parse host ip & port */
    std::string ipAndPort;
    std::getline(transferInfoFile, ipAndPort);
    std::vector<std::string> splitResult;
    boost::split(splitResult, ipAndPort, boost::is_any_of(":"));
    _hostAddress = splitResult[0];
    boost::system::error_code ec;
    boost::asio::ip::address::from_string(_hostAddress, ec);
    if (ec)
    {
        transferInfoFile.close();
        return false;
    }

    _hostPort = splitResult[1];
    for (size_t i = 0; i < _hostPort.size(); ++i)
    {
        if (!isdigit(_hostPort[i]))
        {
            transferInfoFile.close();
            return false;
        }
    }
    int32_t port = std::stoi(_hostPort);
    if (port < 1 || port > UINT16_MAX)
    {
        transferInfoFile.close();
        return false;
    }
    
    /* Parse client name */
    std::getline(transferInfoFile, _clientName);
    if (_clientName.empty() || _clientName.size() > MAX_CLIENT_NAME_SIZE)
    {
        transferInfoFile.close();
        return false;
    }

    /* Parse file name */
    std::getline(transferInfoFile, _fileName);
    if (!boost::filesystem::exists(_rootPath + "\\" + _fileName) && _fileName.size() > BYTES_IN_FILE_NAME)
    {
        transferInfoFile.close();
        return false;
    }

    transferInfoFile.close();
    return true;
}

bool ClientLogic::parseMeInfo()
{
    std::ifstream meInfoFile(_rootPath + "\\me.info");

    /* Parse client name */
    std::string clientNameMeInfo;
    std::getline(meInfoFile, clientNameMeInfo);
    if (_clientName != clientNameMeInfo)
    {
        meInfoFile.close();
        return false;
    }

    /* Parse client ID */
    std::string clientID_ASCII;
    std::getline(meInfoFile, clientID_ASCII);
    if (clientID_ASCII.size() != (BYTES_IN_CLIENT_ID * 2))
    {
        meInfoFile.close();
        return false;
    }
    _clientID = Utilities::UUID::convertUuidFromAsciiToRaw(clientID_ASCII);

    /* Parse RSA private key */
    std::string line;
    std::stringstream ss;
    constexpr size_t MAX_LINES_TO_READ = 16;
    int i = 0;
    while (std::getline(meInfoFile, line) && MAX_LINES_TO_READ > i)
    {
        ss << line;
        ++i;
    }
    _privateKeyBase64 = ss.str();
    if (!RSAPrivateWrapper::validatePrivateKey(Base64Wrapper::decode(_privateKeyBase64)))
    {
        return false;
    }

    meInfoFile.close();
    return true;
}
