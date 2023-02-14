#include "ClientLogic.h"
#include "Utilities.h"

#include "Base64Wrapper.h"

#include <boost/filesystem.hpp>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>


ClientLogic::ClientLogic(const std::string& rootPath) : 
    _rootPath(rootPath), _checksum(0),
    _rsaPrivateWrapper(nullptr), _aesWrapper(nullptr)
{
}

ClientLogic::~ClientLogic()
{
    delete _rsaPrivateWrapper;
    delete _aesWrapper;
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
    std::string hostAddress, hostPort;

    /* Parse host ip */
    std::getline(transferInfoFile, hostAddress, ':');
    boost::system::error_code ec;
    boost::asio::ip::address::from_string(hostAddress, ec);
    if (ec)  // Make sure this is a valid ip address
    {
        transferInfoFile.close();
        return false;
    }
    _hostAddress = hostAddress;

    /* Parse host port */
    std::getline(transferInfoFile, hostPort);
    for (size_t i = 0; i < hostPort.size(); ++i)
    {
        if (!isdigit(hostPort[i]))
        {
            transferInfoFile.close();
            return false;
        }
    }  // By this point, port is definetly a positive integer
    int32_t port = std::stoi(hostPort);
    if (port < 1 || port > UINT16_MAX)
    {
        transferInfoFile.close();
        return false;
    }
    _hostPort = hostPort;
    
    /* Parse client name */
    std::string clientName;
    std::getline(transferInfoFile, clientName);
    if (clientName.empty() || clientName.size() > _maxClientNameLength)
    {
        transferInfoFile.close();
        return false;
    }
    _clientName = clientName;

    /* Parse file name */
    std::string fileName;
    std::getline(transferInfoFile, fileName);
    if (!boost::filesystem::exists(_rootPath + "\\" + fileName) && fileName.size() > BYTES_IN_FILE_NAME)
    {
        transferInfoFile.close();
        return false;
    }
    _fileName = fileName;

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
    std::stringstream ss;
    ss << meInfoFile.rdbuf();

    try
    {
        // Create a temp RSA wrapper to test if key is valid, without allocating heap memory.
        RSAPrivateWrapper testRsaWrapper(Base64Wrapper::decode(ss.str()));
    }
    catch (const std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
        meInfoFile.close();
        return false;
    }
    _rsaPrivateWrapper = new RSAPrivateWrapper(Base64Wrapper::decode(ss.str()));

    meInfoFile.close();
    return true;
}

Response::ResponseCode ClientLogic::handleLogin(tcp::socket& s)
{
    // TODO: add printings
    try
    {
        /* Send login request */
        Request::Request_ClientNamePayload request;
        request.pack(_clientID.data(), _version, Request::LOGIN, _clientName.c_str());
        boost::asio::write(s, boost::asio::buffer(&request, sizeof(request)));

        /* Receive response header */
        uint8_t serverVersion;
        uint16_t responseCode;
        uint32_t payloadSize;
        Response::ResponseHeader responseHeader;
        boost::asio::read(s, boost::asio::buffer(&responseHeader, sizeof(responseHeader)));
        responseHeader.unpack(serverVersion, responseCode, payloadSize);

        /* Analize response */
        if (Response::LOGIN_SUCCESS == responseCode)
        {
            /* Receive response payload */
            std::vector<uint8_t> clientID, encryptedAesKey;
            Response::Response_EncryptedAesPayload responsePayload;
            boost::asio::read(s, boost::asio::buffer(&responsePayload, sizeof(responsePayload)));
            responsePayload.unpack(clientID, encryptedAesKey);

            /* Validate arguments */
            if (_clientID != clientID)
            {
                throw std::invalid_argument("Client ID received from server is incorrect.");
            }

            /* Parse encrypted AES key */
            std::string decryptedAesKey = _rsaPrivateWrapper->decrypt((char*)encryptedAesKey.data(), encryptedAesKey.size());
            _aesWrapper = new AESWrapper((uint8_t*)decryptedAesKey.c_str(), decryptedAesKey.size());

            return Response::LOGIN_SUCCESS;
        }
        else if (Response::LOGIN_FAILURE == responseCode)
        {
            /* Receive response payload */
            std::vector<uint8_t> clientID;
            Response::Response_ClientIDPayload responsePayload;
            boost::asio::read(s, boost::asio::buffer(&responsePayload, sizeof(responsePayload)));

            /* Validate arguments */
            if (_clientID != clientID)
            {
                throw std::invalid_argument("Client ID received from server is incorrect.");
            }
            return Response::LOGIN_FAILURE;
        }
        /* All other response codes are treated as 'Response::GENERAL_FAILURE'. */
    }
    catch (const std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    return Response::GENERAL_FAILURE;
}

Response::ResponseCode ClientLogic::handleRegistration(tcp::socket& s)
{
    // TODO: add printings
    try
    {
        /* Send registration request */
        Request::Request_ClientNamePayload request;
        uint8_t nullID[BYTES_IN_CLIENT_ID] = { 0 };
        request.pack(nullID, _version, Request::REGISTER, _clientName.c_str());
        boost::asio::write(s, boost::asio::buffer(&request, sizeof(request)));

        /* Receive response header */
        uint8_t serverVersion;
        uint16_t responseCode;
        uint32_t payloadSize;
        Response::ResponseHeader responseHeader;
        boost::asio::read(s, boost::asio::buffer(&responseHeader, sizeof(responseHeader)));
        responseHeader.unpack(serverVersion, responseCode, payloadSize);

        /* Analize response */
        if (Response::REGISTER_SUCCESS == responseCode)
        {
            /* Receive response payload */
            Response::Response_ClientIDPayload responsePayload;
            boost::asio::read(s, boost::asio::buffer(&responsePayload, sizeof(responsePayload)));
            responsePayload.unpack(_clientID);

            return Response::REGISTER_SUCCESS;
        }
        else if (Response::REGISTER_FAILURE == responseCode)
        {
            return Response::REGISTER_FAILURE;
        }
        /* All other response codes are treated as 'Response::GENERAL_FAILURE'. */
    }
    catch (const std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    return Response::GENERAL_FAILURE;
}

Response::ResponseCode ClientLogic::handleKeyExchange(tcp::socket& s)
{
    // TODO: add printings
    try
    {
        /* Send key exchange request */
        Request::Request_PublicKeyPayload request;
        request.pack(_clientID.data(), _version, Request::LOGIN, _clientName.c_str(), (uint8_t*)_rsaPrivateWrapper->getPublicKey().c_str());
        boost::asio::write(s, boost::asio::buffer(&request, sizeof(request)));

        /* Receive response header */
        uint8_t serverVersion;
        uint16_t responseCode;
        uint32_t payloadSize;
        Response::ResponseHeader responseHeader;
        boost::asio::read(s, boost::asio::buffer(&responseHeader, sizeof(responseHeader)));
        responseHeader.unpack(serverVersion, responseCode, payloadSize);

        if (Response::PUBLIC_KEY_RECEIVED == responseCode)
        {
            /* Receive response payload */
            std::vector<uint8_t> clientID, encryptedAesKey;
            Response::Response_EncryptedAesPayload responsePayload;
            boost::asio::read(s, boost::asio::buffer(&responsePayload, sizeof(responsePayload)));
            responsePayload.unpack(clientID, encryptedAesKey);

            /* Validate arguments */
            if (_clientID != clientID)
            {
                throw std::invalid_argument("Client ID received from server is incorrect.");
            }

            /* Parse encrypted AES key */
            std::string decryptedAesKey = _rsaPrivateWrapper->decrypt((char*)encryptedAesKey.data(), encryptedAesKey.size());
            _aesWrapper = new AESWrapper((uint8_t*)decryptedAesKey.c_str(), decryptedAesKey.size());

            return Response::PUBLIC_KEY_RECEIVED;
        }
        /* All other response codes are treated as 'Response::GENERAL_FAILURE'. */
    }
    catch (const std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    return Response::GENERAL_FAILURE;
}

Response::ResponseCode ClientLogic::handleFileBackup(tcp::socket& s, const std::string& filePath)
{
    std::ifstream file;
    try
    {
        // TODO: Need to validate file size before sending.
        // TODO: Need to calculate CRC before sending.
        // TODO: Need to encrypt file before sending.

        /* Send file backup request */
        Request::Request_FilePayload request;
        const size_t fileSize = boost::filesystem::file_size(filePath);
        request.pack(_clientID.data(), _version, Request::BACKUP_FILE, static_cast<uint32_t>(fileSize), _fileName.c_str());
        boost::asio::write(s, boost::asio::buffer(&request, sizeof(request)));

        /* Send the file itself */
        file.open(filePath, std::ifstream::binary);
        if (!file.is_open())
        {
            return Response::GENERAL_FAILURE;
        }

        constexpr size_t PACKET_SIZE = 1024;
        char buffer[PACKET_SIZE] = { 0 };
        size_t bytesRemaining = fileSize;

        while (bytesRemaining)
        {
            memset(buffer, 0, PACKET_SIZE);
            size_t bufferSize = std::min(bytesRemaining, static_cast<size_t>(PACKET_SIZE));
            file.read(buffer, bufferSize);
            bytesRemaining -= boost::asio::write(s, boost::asio::buffer(buffer, bufferSize));
        }
        file.close();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    file.close();
    return Response::GENERAL_FAILURE;
}
