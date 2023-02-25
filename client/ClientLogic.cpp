#include "ClientLogic.h"
#include "Utilities.h"

#include "Base64Wrapper.h"

#include <boost/filesystem.hpp>

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <typeinfo>
#include <vector>


void printResponseHeader(const uint8_t serverVersion, const uint16_t responseCode, const uint32_t payloadSize)
{
    std::cout << "Response received:\n" <<
        "(1) Server version = " << static_cast<int>(serverVersion) << "\n" <<
        "(2) Response code = " << responseCode << "\n" <<
        "(3) Payload size = " << payloadSize << std::endl;
}

ClientLogic::ClientLogic(const std::string& rootPath) : 
    _rootPath(rootPath), _checksum(0), _needToRegister(false),
    _rsaPrivateWrapper(nullptr), _aesWrapper(nullptr)
{
    std::cout << "Created ClientLogic with root path: " + _rootPath << std::endl;
}

ClientLogic::~ClientLogic()
{
    delete _rsaPrivateWrapper;
    delete _aesWrapper;
}

bool ClientLogic::initialize()
{
    std::cout << "Beginning initialization phase" << std::endl;
    std::stringstream errorMessage;
    /* Parse transfer.info file */
    if (!parseTransferInfo(errorMessage))
    {
        // transfer.info might not exist or is corrupted
        std::cerr << "Error parsing transfer.info: " << errorMessage.str() << std::endl;
        return false;
    }
    // transfer.info parsed successfuly
    std::cout << "Success parsing transfer.info with the following parameters:\n"
        "(1) Host address: " << _hostAddress << "\n"
        "(2) Host port: " << _hostPort << "\n"
        "(3) Client name: " << _clientName << "\n"
        "(4) File name: " << _fileName << std::endl;

    /* Parse me.info file */
    if (boost::filesystem::exists(_rootPath + "\\me.info"))
    {
        if (!parseMeInfo(errorMessage))  // me.info exists, parse it
        {
            // me.info info is corrupted
            std::cerr << "Error parsing me.info: " << errorMessage.str() << std::endl;
            return false;
        }
        std::cout << "\nSuccess parsing me.info with the following parameters:\n"
            "(1) Client name: " << _clientName << "\n"
            "(2) Client ID: " << Utilities::UUID::convertUuidFromRawToAscii(_clientID) << "\n"
            "(3) Private key is valid" << std::endl;
        _needToRegister = false;
    }
    else
    {
        _needToRegister = true;
    }

    // Check file size according to the following formula:
    // cipherLen = ( cleanLen/16 + 1) * 16
    // AES block size is 16
    const size_t fileSize = boost::filesystem::file_size(_rootPath + "\\" + _fileName);
    const size_t encryptedFileSize = (fileSize / 16 + 1) * 16;
    if (encryptedFileSize > _maxTransferSize)
    {
        std::cerr << "File is too large to transfer (file size = " << fileSize << ", max size = " << _maxTransferSize << ")";
        return false;
    }
    std::cout << "Size of file: " << _fileName << " is: " << fileSize << " bytes" << std::endl;
    std::cout << "Size of file: " << _fileName << " after encryption is: " << encryptedFileSize << " bytes" << std::endl;

    /* Calculate CRC of file */
    try
    {
        _checksum = Utilities::CRC::calculateFileCRC(_rootPath + "\\" + _fileName);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error calculating checksum of file: " << _fileName <<
            " (Exception: " << e.what() << ")" << std::endl;
        return false;
    }
    std::cout << "Success calculating checksum of file: " << _fileName <<
        " (checksum = " << _checksum << ")" << std::endl;

    std::cout << "Finished initialization phase" << std::endl;
    return true;
}

bool ClientLogic::run()
{
    std::cout << "Beginning runtime phase" << std::endl;
    bool success = false;
    boost::asio::io_context io_context;
    tcp::socket socket(io_context);
    tcp::resolver resolver(io_context);

    try
    {
        std::cout << "Connecting to server " << _hostAddress << ":" << _hostPort << std::endl;
        boost::asio::connect(socket, resolver.resolve(_hostAddress, _hostPort));
        std::cout << "Successfully connected to server" << std::endl;

        constexpr int NUMBER_OF_RETRIES = 3;
        bool finished = false;
        int retryCount;
        Request::RequestCode currentRequest = _needToRegister ? Request::REGISTER : Request::LOGIN;
        while (!finished)
        {
            // retryCount is initialized this way so there would be three attempts to send a file.
            retryCount = (currentRequest == Request::CRC_INVALID_RETRYING) ? 2 : 1;
            for (; retryCount <= NUMBER_OF_RETRIES; ++retryCount)
            {
                if (Request::REGISTER == currentRequest &&
                    Response::REGISTER_SUCCESS == handleRegistration(socket))
                {
                    std::cout << "Successfully registered to server" << std::endl;
                    currentRequest = Request::KEY_EXCHANGE;
                    break;
                }
                else if (Request::LOGIN == currentRequest)
                {
                    uint16_t rc = handleLogin(socket);
                    if (Response::LOGIN_SUCCESS == rc)
                    {
                        std::cout << "Successfully logged in to server" << std::endl;
                        currentRequest = Request::BACKUP_FILE;
                        break;
                    }
                    else if (Response::LOGIN_FAILURE == rc)
                    {
                        currentRequest = Request::REGISTER;
                        break;
                    }
                }
                else if (currentRequest == Request::KEY_EXCHANGE &&
                    Response::PUBLIC_KEY_RECEIVED == handleKeyExchange(socket))
                {
                    std::cout << "Successfully exchanged keys with server" << std::endl;
                    currentRequest = Request::BACKUP_FILE;
                    break;
                }
                else if (currentRequest == Request::BACKUP_FILE)
                {
                    uint32_t checksum;
                    if (Response::FILE_RECEIVED == handleFileBackup(socket, checksum))
                    {
                        if (_checksum == checksum)
                        {
                            std::cout << "Successfully backed up file" << std::endl;
                            currentRequest = Request::CRC_VALID;
                            break;
                        }
                        else
                        {
                            std::cout << "CRC is invalid. Retrying..." << std::endl;
                            currentRequest = Request::CRC_INVALID_RETRYING;
                            break;
                        }
                    }
                }
                else if (currentRequest == Request::CRC_VALID &&
                    Response::ACKNOWLEDGE == handleValidCRC(socket))
                {
                    success = true;
                    finished = true;
                    break;
                }
                else if (currentRequest == Request::CRC_INVALID_RETRYING)
                {
                    uint32_t checksum;
                    if (Response::FILE_RECEIVED == handleInvalidCRC(socket, checksum))
                    {
                        if (_checksum == checksum)
                        {
                            currentRequest = Request::CRC_VALID;
                            break;
                        }
                        else
                        {
                            std::cout << "CRC is invalid. Retrying... (retry count = " << retryCount << ")" << std::endl;
                            continue;
                        }
                    }
                }
                else if (currentRequest == Request::CRC_INVALID_ABORTING &&
                    Response::ACKNOWLEDGE == handleAbort(socket))
                {
                    finished = true;
                    break;
                }
                std::cout << "Server responded with an error (request code = " << currentRequest <<
                    "). Retrying... (retry count = " << retryCount << ")" << std::endl;
            }  // End of for loop
            if (NUMBER_OF_RETRIES < retryCount)
            {
                throw std::runtime_error("Maximum number of retries reached (request code = " + std::to_string(currentRequest) + ")");
            }
        }  // End of while loop
    }
    catch (const std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    std::cout << "Finished runtime phase" << std::endl;
    return success;
}

bool ClientLogic::parseTransferInfo(std::stringstream& errorMessage)
{
    std::ifstream transferInfoFile(_rootPath + "\\transfer.info");
    if (!transferInfoFile.is_open())
    {
        errorMessage << "Could not open transfer.info";
        return false;
    }
    std::string hostAddress, hostPort;

    /* Parse host ip */
    std::getline(transferInfoFile, hostAddress, ':');
    boost::system::error_code ec;
    boost::asio::ip::address::from_string(hostAddress, ec);
    if (ec)  // Make sure this is a valid ip address
    {
        errorMessage << "Invalid IP address: " << hostAddress;
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
            errorMessage << "Invalid port number: " << hostPort;
            transferInfoFile.close();
            return false;
        }
    }  // By this point, port is definetly a positive integer
    int32_t port = std::stoi(hostPort);
    if (port < 1 || port > UINT16_MAX)
    {
        errorMessage << "Invalid port number: " << hostPort;
        transferInfoFile.close();
        return false;
    }
    _hostPort = hostPort;
    
    /* Parse client name */
    std::string clientName;
    std::getline(transferInfoFile, clientName);
    if (clientName.empty() || clientName.size() > _maxClientNameLength)
    {
        errorMessage << "Invalid client name";
        transferInfoFile.close();
        return false;
    }
    _clientName = clientName;

    /* Parse file name */
    std::string fileName;
    std::getline(transferInfoFile, fileName);
    if (!boost::filesystem::exists(_rootPath + "\\" + fileName) || fileName.size() > BYTES_IN_FILE_NAME)
    {
        errorMessage << "Invalid file name";
        transferInfoFile.close();
        return false;
    }
    _fileName = fileName;

    transferInfoFile.close();
    return true;
}

bool ClientLogic::parseMeInfo(std::stringstream& errorMessage)
{
    std::ifstream meInfoFile(_rootPath + "\\me.info");
    if (!meInfoFile.is_open())
    {
        errorMessage << "Could not open me.info";
        return false;
    }

    /* Parse client name */
    std::string clientNameMeInfo;
    std::getline(meInfoFile, clientNameMeInfo);
    if (_clientName != clientNameMeInfo)
    {
        errorMessage << "Client name in me.info does not match client name in transfer.info";
        meInfoFile.close();
        return false;
    }

    /* Parse client ID */
    std::string clientID_ASCII;
    std::getline(meInfoFile, clientID_ASCII);
    if (clientID_ASCII.size() != (BYTES_IN_CLIENT_ID * 2))
    {
        errorMessage << "Invalid client ID";
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
        errorMessage << "Invalid private key (Exception: " << e.what() << ")";
        meInfoFile.close();
        return false;
    }
    _rsaPrivateWrapper = new RSAPrivateWrapper(Base64Wrapper::decode(ss.str()));

    meInfoFile.close();
    return true;
}

uint16_t ClientLogic::handleLogin(tcp::socket& s)
{
    /* Send login request */
    std::cout << "\nSending login request" << std::endl;
    Request::Request_ClientNamePayload request;
    request.pack(_clientID.data(), _version, Request::LOGIN, _clientName);
    boost::asio::write(s, boost::asio::buffer(&request, sizeof(request)));

    /* Receive response header */
    uint8_t serverVersion;
    uint16_t responseCode;
    uint32_t payloadSize;
    Response::ResponseHeader responseHeader;
    boost::asio::read(s, boost::asio::buffer(&responseHeader, sizeof(responseHeader)));
    responseHeader.unpack(serverVersion, responseCode, payloadSize);
    printResponseHeader(serverVersion, responseCode, payloadSize);

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
        std::string decryptedAesKey = _rsaPrivateWrapper->decrypt((char*)encryptedAesKey.data(), BYTES_IN_ENCRYPTED_AES_KEY);
        _aesWrapper = new AESWrapper((uint8_t*)decryptedAesKey.c_str(), BYTES_IN_AES_KEY);
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
    }
    else if (Response::GENERAL_FAILURE != responseCode)
    {
        throw std::runtime_error("Server's response code does not match protocol");
    }
    return responseCode;
}

uint16_t ClientLogic::handleRegistration(tcp::socket& s)
{
    /* Send registration request */
    std::cout << "\nSending registration request" << std::endl;
    Request::Request_ClientNamePayload request;
    uint8_t nullID[BYTES_IN_CLIENT_ID] = { 0 };
    request.pack(nullID, _version, Request::REGISTER, _clientName);
    boost::asio::write(s, boost::asio::buffer(&request, sizeof(request)));

    /* Receive response header */
    uint8_t serverVersion;
    uint16_t responseCode;
    uint32_t payloadSize;
    Response::ResponseHeader responseHeader;
    boost::asio::read(s, boost::asio::buffer(&responseHeader, sizeof(responseHeader)));
    responseHeader.unpack(serverVersion, responseCode, payloadSize);
    printResponseHeader(serverVersion, responseCode, payloadSize);

    /* Analize response */
    if (Response::REGISTER_SUCCESS == responseCode)
    {
        /* Receive response payload */
        Response::Response_ClientIDPayload responsePayload;
        boost::asio::read(s, boost::asio::buffer(&responsePayload, sizeof(responsePayload)));
        responsePayload.unpack(_clientID);
        
        /* Create me.info file */
        std::stringstream ss;
        ss << _clientName << "\n" << Utilities::UUID::convertUuidFromRawToAscii(_clientID) << "\n";
        if (nullptr == _rsaPrivateWrapper)
        {
            _rsaPrivateWrapper = new RSAPrivateWrapper();
        }
        ss << Base64Wrapper::encode(_rsaPrivateWrapper->getPrivateKey());
        std::ofstream meInfoFile;
        meInfoFile.exceptions(std::ofstream::badbit);
        meInfoFile.open(_rootPath + "\\me.info");
        meInfoFile << ss.str();
        meInfoFile.close();
    }
    else if (Response::REGISTER_FAILURE == responseCode)
    {
        throw std::runtime_error("Failed to register to server");
    }
    else if (Response::GENERAL_FAILURE != responseCode)
    {
        throw std::runtime_error("Server's response code does not match protocol");
    }
    return responseCode;
}

uint16_t ClientLogic::handleKeyExchange(tcp::socket& s)
{
    /* Send key exchange request */
    std::cout << "\nSending key exchange request" << std::endl;
    Request::Request_PublicKeyPayload request;
    request.pack(_clientID.data(), _version, Request::KEY_EXCHANGE, _clientName, (uint8_t*)_rsaPrivateWrapper->getPublicKey().c_str());
    boost::asio::write(s, boost::asio::buffer(&request, sizeof(request)));

    /* Receive response header */
    uint8_t serverVersion;
    uint16_t responseCode;
    uint32_t payloadSize;
    Response::ResponseHeader responseHeader;
    boost::asio::read(s, boost::asio::buffer(&responseHeader, sizeof(responseHeader)));
    responseHeader.unpack(serverVersion, responseCode, payloadSize);
    printResponseHeader(serverVersion, responseCode, payloadSize);

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
            throw std::invalid_argument("Client ID received from server is incorrect");
        }

        /* Parse encrypted AES key */
        std::string decryptedAesKey = _rsaPrivateWrapper->decrypt((char*)encryptedAesKey.data(), BYTES_IN_ENCRYPTED_AES_KEY);
        _aesWrapper = new AESWrapper((uint8_t*)decryptedAesKey.c_str(), BYTES_IN_AES_KEY);
    }
    else if (Response::GENERAL_FAILURE != responseCode)
    {
        throw std::runtime_error("Server's response code does not match protocol");
    }
    return responseCode;
}

uint16_t ClientLogic::handleFileBackup(tcp::socket& s, uint32_t& checksum)
{
    /* Encrypt file before sending */
    const std::string encryptedFilePath = _aesWrapper->encryptFile(_rootPath + "\\" + _fileName);
    const size_t encryptedFileSize = boost::filesystem::file_size(encryptedFilePath);

    /* Open the encrypted file for reading */
    std::ifstream encryptedFile;
    encryptedFile.exceptions(std::ios::badbit);
    encryptedFile.open(encryptedFilePath, std::ios::binary);

    /* Send file backup request */
    std::cout << "\nSending file backup request" << std::endl;
    Request::Request_FilePayload request;
    request.pack(_clientID.data(), _version, Request::BACKUP_FILE, static_cast<uint32_t>(encryptedFileSize), _fileName);
    boost::asio::write(s, boost::asio::buffer(&request, sizeof(request)));

    /* Send the file itself */
    constexpr size_t PACKET_SIZE = 1024;
    char buffer[PACKET_SIZE] = { 0 };
    size_t bytesRemaining = encryptedFileSize;

    std::cout << "Backing up file..." << std::endl;
    while (bytesRemaining)
    {
        memset(buffer, 0, PACKET_SIZE);
        size_t bufferSize = std::min(bytesRemaining, static_cast<size_t>(PACKET_SIZE));
        encryptedFile.read(buffer, bufferSize);
        bytesRemaining -= boost::asio::write(s, boost::asio::buffer(buffer, bufferSize));
    }
    encryptedFile.close();
    boost::filesystem::remove(encryptedFilePath);  // remove temp file

    /* Receive response header */
    uint8_t serverVersion;
    uint16_t responseCode;
    uint32_t payloadSize;
    Response::ResponseHeader responseHeader;
    boost::asio::read(s, boost::asio::buffer(&responseHeader, sizeof(responseHeader)));
    responseHeader.unpack(serverVersion, responseCode, payloadSize);
    printResponseHeader(serverVersion, responseCode, payloadSize);

    if (Response::FILE_RECEIVED == responseCode)
    {
        /* Receive response payload */
        std::vector<uint8_t> clientID;
        std::string fileName;
        uint32_t contentSize;
        Response::Response_CrcPayload responsePayload;
        boost::asio::read(s, boost::asio::buffer(&responsePayload, sizeof(responsePayload)));
        responsePayload.unpack(clientID, contentSize, fileName, checksum);

        /* Validate arguments */
        if (_clientID != clientID)
        {
            throw std::invalid_argument("Client ID received from server is incorrect");
        }
        if (_fileName != fileName)
        {
            throw std::invalid_argument("File name received from server is incorrect");
        }
        if (encryptedFileSize != contentSize)
        {
            throw std::invalid_argument("Content size received from server is incorrect");
        }
    }
    else if (Response::GENERAL_FAILURE != responseCode)
    {
        throw std::runtime_error("Server's response code does not match protocol");
    }
    return responseCode;
}

uint16_t ClientLogic::handleValidCRC(tcp::socket& s)
{
    /* Send CRC valid request */
    std::cout << "\nSending valid CRC request" << std::endl;
    Request::Request_FileNamePayload request;
    request.pack(_clientID.data(), _version, Request::CRC_VALID, _fileName);
    boost::asio::write(s, boost::asio::buffer(&request, sizeof(request)));

    /* Receive response header */
    uint8_t serverVersion;
    uint16_t responseCode;
    uint32_t payloadSize;
    Response::ResponseHeader responseHeader;
    boost::asio::read(s, boost::asio::buffer(&responseHeader, sizeof(responseHeader)));
    responseHeader.unpack(serverVersion, responseCode, payloadSize);
    printResponseHeader(serverVersion, responseCode, payloadSize);

    if (Response::ACKNOWLEDGE == responseCode)
    {
        /* Receive response payload */
        std::vector<uint8_t> clientID;
        Response::Response_ClientIDPayload responsePayload;
        boost::asio::read(s, boost::asio::buffer(&responsePayload, sizeof(responsePayload)));
        responsePayload.unpack(clientID);

        /* Validate arguments */
        if (_clientID != clientID)
        {
            throw std::invalid_argument("Client ID received from server is incorrect");
        }
    }
    else if (Response::GENERAL_FAILURE != responseCode)
    {
        throw std::runtime_error("Server's response code does not match protocol");
    }
    return responseCode;
}

uint16_t ClientLogic::handleInvalidCRC(tcp::socket& s, uint32_t& checksum)
{
    /* Send CRC invalid request */
    std::cout << "\nSending invalid CRC request" << std::endl;
    Request::Request_FileNamePayload request;
    request.pack(_clientID.data(), _version, Request::CRC_INVALID_RETRYING, _fileName);
    boost::asio::write(s, boost::asio::buffer(&request, sizeof(request)));

    /* Send the file again */
    return handleFileBackup(s, checksum);
}

uint16_t ClientLogic::handleAbort(tcp::socket& s)
{
    /* Send abort request */
    std::cout << "\nSending abort request" << std::endl;
    Request::Request_FileNamePayload request;
    request.pack(_clientID.data(), _version, Request::CRC_INVALID_ABORTING, _fileName);
    boost::asio::write(s, boost::asio::buffer(&request, sizeof(request)));

    /* Receive response header */
    uint8_t serverVersion;
    uint16_t responseCode;
    uint32_t payloadSize;
    Response::ResponseHeader responseHeader;
    boost::asio::read(s, boost::asio::buffer(&responseHeader, sizeof(responseHeader)));
    responseHeader.unpack(serverVersion, responseCode, payloadSize);
    printResponseHeader(serverVersion, responseCode, payloadSize);

    if (Response::ACKNOWLEDGE == responseCode)
    {
        /* Receive response payload */
        std::vector<uint8_t> clientID;
        Response::Response_ClientIDPayload responsePayload;
        boost::asio::read(s, boost::asio::buffer(&responsePayload, sizeof(responsePayload)));
        responsePayload.unpack(clientID);

        /* Validate arguments */
        if (_clientID != clientID)
        {
            throw std::invalid_argument("Client ID received from server is incorrect");
        }
    }
    else if (Response::GENERAL_FAILURE)
    {
        throw std::runtime_error("Server's response code does not match protocol");
    }
    return responseCode;
}
