#include "Parser.h"
#include "Protocol.h"
#include "Utilities.h"
#include "RSAWrapper.h"
#include "Base64Wrapper.h"

#include <boost/filesystem.hpp>
#include <boost/asio.hpp>

#include <fstream>


bool Parser::parseTransferInfo(std::stringstream& errMsg)
{
    /* Check if transfer.info exists */
    std::ifstream transferInfoFile("transfer.info");
    if (!transferInfoFile.is_open())
    {
        errMsg << "Could not open transfer.info";
        return false;
    }

    /* Parse ip address and port number */
    std::string hostAddress, hostPort;
    std::getline(transferInfoFile, hostAddress, ':');
    boost::system::error_code ec;
    boost::asio::ip::address::from_string(hostAddress, ec);
    if (ec)  // Make sure this is a valid ip address.
    {
        errMsg << "Invalid IP address: " << hostAddress;
        transferInfoFile.close();
        return false;
    }
    std::getline(transferInfoFile, hostPort);
    for (size_t i = 0; i < hostPort.size(); ++i)
    {
        if (!isdigit(hostPort[i]))
        {
            errMsg << "Invalid port number: " << hostPort;
            transferInfoFile.close();
            return false;
        }
    }  // By this point, port is definetly a positive integer.
    int32_t port = std::stoi(hostPort);
    if (port < 1 || port > UINT16_MAX)
    {
        errMsg << "Invalid port number: " << hostPort;
        transferInfoFile.close();
        return false;
    }
    _hostPort = hostPort;
    _hostAddress = hostAddress;

    /* Parse client name */
    std::string clientName;
    std::getline(transferInfoFile, clientName);
    if (clientName.empty() || clientName.size() > MAX_CLIENT_NAME_LEN)
    {
        errMsg << "Invalid client name";
        transferInfoFile.close();
        return false;
    }
    _clientName = clientName;

    /* Parse file path and name */
    std::string path;
    std::getline(transferInfoFile, path);
    boost::filesystem::path filePath(path);
    if (!boost::filesystem::exists(filePath) || !boost::filesystem::is_regular_file(filePath))
    {
        errMsg << "Invalid file path: " << filePath;
        transferInfoFile.close();
        return false;
    }
    if (filePath.filename().string().size() >= BYTES_IN_FILE_NAME)
    {
        errMsg << "Invalid file name: " << filePath;
        transferInfoFile.close();
        return false;
    }
    _filePath = filePath.string();
    _fileName = filePath.filename().string();

    transferInfoFile.close();
    return true;
}


bool Parser::parseMeInfo(std::stringstream& errMsg)
{
    std::ifstream meInfoFile("me.info");
    if (!meInfoFile.is_open())
    {
        errMsg << "Could not open me.info";
        return false;
    }

    /* Parse client name */
    std::string clientNameMeInfo;
    std::getline(meInfoFile, clientNameMeInfo);
    if (_clientName != clientNameMeInfo)
    {
        errMsg << "Client name in me.info does not match client name in transfer.info";
        meInfoFile.close();
        return false;
    }

    /* Parse client ID */
    std::string clientID_ASCII;
    std::getline(meInfoFile, clientID_ASCII);
    if (clientID_ASCII.size() != (BYTES_IN_CLIENT_ID * 2))
    {
        errMsg << "Invalid client ID";
        meInfoFile.close();
        return false;
    }
    _clientID = Utilities::UUID::convertUuidFromAsciiToRaw(clientID_ASCII);

    /* Parse RSA private key */
    std::stringstream ss;
    ss << meInfoFile.rdbuf();
    try
    {
        // Create a temp RSA wrapper to test if key is valid, without allocating heap memory.
        RSAPrivateWrapper testRsaWrapper(Base64Wrapper::decode(ss.str()));
    }
    catch (const std::exception& e)
    {
        errMsg << "Invalid private key (Exception: " << e.what() << ")";
        meInfoFile.close();
        return false;
    }
    _privateKeyBase64 = ss.str();

    meInfoFile.close();
    return true;
}


std::string Parser::getHostAddress()
{
    return _hostAddress;
}


std::string Parser::getHostPort()
{
    return _hostPort;
}


std::string Parser::getClientName()
{
    return _clientName;
}


std::string Parser::getFilePath()
{
    return _filePath;
}


std::string Parser::getFileName()
{
    return _fileName;
}


std::string Parser::getPrivateKeyBase64()
{
    return _privateKeyBase64;
}


std::vector<uint8_t> Parser::getClientID()
{
    return _clientID;
}
