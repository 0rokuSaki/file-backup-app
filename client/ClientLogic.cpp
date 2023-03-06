/*****************************************************************//**
 * \file   ClientLogic.cpp
 * \brief  ClientLogic class implementation.
 * 
 * \author aaron
 * \date   March 2023
 *********************************************************************/
#include <boost/filesystem.hpp>
#include <iostream>
#include <fstream>
#include <sstream>

#include "Base64Wrapper.h"
#include "ClientLogic.h"
#include "Utilities.h"
#include "Session.h"


void printResponseHeader(const uint8_t serverVersion, const uint16_t responseCode, const uint32_t payloadSize)
{
    std::cout << "Response received:\n" <<
        "(1) Server version = " << static_cast<int>(serverVersion) << "\n" <<
        "(2) Response code = " << responseCode << "\n" <<
        "(3) Payload size = " << payloadSize << std::endl;
}

ClientLogic::ClientLogic() : _checksum(0), _needToRegister(false),
    _rsaPrivateWrapper(nullptr), _aesWrapper(nullptr), _session(&Session::getInstance())
{
    std::cout << "Created ClientLogic" << std::endl;
}

ClientLogic::~ClientLogic()
{
    delete _rsaPrivateWrapper;
    delete _aesWrapper;
}

bool ClientLogic::initialize()
{
    std::stringstream errorMessage;
    /* Parse transfer.info file */
    if (!parseTransferInfo(errorMessage))
    {
        std::cerr << "Error parsing transfer.info: " << errorMessage.str() << std::endl;
        return false;
    }
    std::cout << "Success parsing transfer.info with the following parameters:\n"
        "(1) Host address: " << _hostAddress << "\n"
        "(2) Host port: " << _hostPort << "\n"
        "(3) Client name: " << _clientName << "\n"
        "(4) File name: " << _fileName << std::endl;

    /* Parse me.info file */
    if (boost::filesystem::exists("me.info"))
    {
        if (!parseMeInfo(errorMessage))
        {
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
    // cipherLen = (cleanLen/16 + 1) * 16
    // AES block size is 16
    const size_t fileSize = boost::filesystem::file_size(_filePath);
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
        _checksum = Utilities::CRC::calculateFileCRC(_filePath);
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
    try
    {
        std::cout << "Connecting to server " << _hostAddress << ":" << _hostPort << std::endl;
        _session->connect(_hostAddress, _hostPort);
        std::cout << "Successfully connected to server" << std::endl;

        constexpr int NUMBER_OF_RETRIES = 3;
        Request::RequestCode currentRequest = _needToRegister ? Request::REGISTER : Request::LOGIN;
        while (true)
        {
            uint16_t rc = 0;
            // retryCount is initialized this way so there would be three attempts to send a file.
            int retryCount = (currentRequest == Request::CRC_INVALID_RETRYING) ? 2 : 1;
            for (; retryCount <= NUMBER_OF_RETRIES; ++retryCount)
            {
                if (Request::REGISTER == currentRequest)
                {
                    rc = handleRegistration();
                    if (Response::REGISTER_SUCCESS == rc)
                    {
                        std::cout << "Successfully registered to server" << std::endl;
                        currentRequest = Request::KEY_EXCHANGE;
                        break;
                    }
                    else if (Response::REGISTER_FAILURE == rc)
                    {
                        std::cout << "Failed to register to server" << std::endl;
                        return false;
                    }
                }
                else if (Request::LOGIN == currentRequest)
                {
                    rc = handleLogin();
                    if (Response::LOGIN_SUCCESS == rc)
                    {
                        std::cout << "Successfully logged in to server" << std::endl;
                        currentRequest = Request::BACKUP_FILE;
                        break;
                    }
                    else if (Response::LOGIN_FAILURE == rc)
                    {
                        std::cout << "Failed to login to server" << std::endl;
                        currentRequest = Request::REGISTER;
                        break;
                    }
                }
                else if (currentRequest == Request::KEY_EXCHANGE)    
                {
                    rc = handleKeyExchange();
                    if (Response::PUBLIC_KEY_RECEIVED == rc)
                    {
                        std::cout << "Successfully exchanged keys with server" << std::endl;
                        currentRequest = Request::BACKUP_FILE;
                        break;
                    }
                }
                else if (currentRequest == Request::BACKUP_FILE)
                {
                    uint32_t checksum;
                    rc = handleFileBackup(checksum);
                    if (Response::FILE_RECEIVED == rc)
                    {
                        if (_checksum == checksum)
                        {
                            std::cout << "Successfully transfered file" << std::endl;
                            currentRequest = Request::CRC_VALID;
                            break;
                        }
                        else
                        {
                            std::cout << "CRC is invalid. Retrying... (retry count = " << retryCount << ")" << std::endl;
                            currentRequest = Request::CRC_INVALID_RETRYING;
                            break;
                        }
                    }
                }
                else if (currentRequest == Request::CRC_VALID)  
                {
                    rc = handleValidCRC();
                    if (Response::ACKNOWLEDGE == rc)
                    {
                        std::cout << "Successfully verified CRC" << std::endl;
                        return true;
                    }
                }
                else if (currentRequest == Request::CRC_INVALID_RETRYING)
                {
                    uint32_t checksum;
                    rc = handleInvalidCRC(checksum);
                    if (Response::FILE_RECEIVED == rc)
                    {
                        if (_checksum == checksum)
                        {
                            currentRequest = Request::CRC_VALID;
                            break;
                        }
                        else if (retryCount < NUMBER_OF_RETRIES)
                        {
                            std::cout << "CRC is invalid. Retrying... (retry count = " << retryCount << ")" << std::endl;
                        }
                        else
                        {
                            std::cout << "CRC is invalid. Aborting... (retry count = " << retryCount << ")" << std::endl;
                        }
                    }
                }
                else if (currentRequest == Request::CRC_INVALID_ABORTING)
                {
                    rc = handleAbort();
                    if (Response::ACKNOWLEDGE == rc)
                    {
                        return false;
                    }
                }
                else if (Response::GENERAL_FAILURE == rc)
                {
                    std::cout << "Server responded with an error (request code = " << currentRequest <<
                        "). Retrying... (retry count = " << retryCount << ")" << std::endl;
                }
                else  // Server's response does not match protocol
                {
                    throw std::runtime_error("Server's response code does not match protocol");
                }
            }  // End of for loop
            if (NUMBER_OF_RETRIES < retryCount)
            {
                std::cout << "Maximum number of retries reached (request code = " + std::to_string(currentRequest) + ")" << std::endl;
                return false;
            }
        }  // End of while loop
    }
    catch (const std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    std::cout << "Finished runtime phase" << std::endl;
    return false;
}

bool ClientLogic::parseTransferInfo(std::stringstream& errorMessage)
{
    std::ifstream transferInfoFile("transfer.info");
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

    /* Parse file path and name */
    std::string path;
    std::getline(transferInfoFile, path);
    boost::filesystem::path filePath(path);
    if (!boost::filesystem::exists(filePath) || !boost::filesystem::is_regular_file(filePath))
    {
        errorMessage << "Invalid file path: " << filePath;
        transferInfoFile.close();
        return false;
    }
    if (filePath.filename().string().size() >= BYTES_IN_FILE_NAME)
    {
        errorMessage << "Invalid file name: " << filePath;
        transferInfoFile.close();
        return false;
    }
    _filePath = filePath.string();
    _fileName = filePath.filename().string();

    transferInfoFile.close();
    return true;
}

bool ClientLogic::parseMeInfo(std::stringstream& errorMessage)
{
    std::ifstream meInfoFile("me.info");
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

uint16_t ClientLogic::handleLogin()
{
    /* Send login request */
    std::cout << "\nSending login request" << std::endl;
    Request::Request_ClientNamePayload request(_clientID.data(), _version, Request::LOGIN, _clientName);
    _session->write(request);

    /* Receive response header */
    Response::ResponseHeader responseHeader;
    Session::getInstance().read(responseHeader);
    printResponseHeader(responseHeader.version, responseHeader.code, responseHeader.payloadSize);

    /* Analize response */
    if (Response::LOGIN_SUCCESS == responseHeader.code)
    {
        /* Receive response payload */
        Response::Response_EncryptedAesPayload responsePayload;
        _session->read(responsePayload);

        validateClientID(responsePayload.clientID);

        /* Parse encrypted AES key */
        std::string decryptedAesKey = _rsaPrivateWrapper->decrypt((char*)responsePayload.encryptedAesKey, BYTES_IN_ENCRYPTED_AES_KEY);
        _aesWrapper = new AESWrapper((uint8_t*)decryptedAesKey.c_str(), BYTES_IN_AES_KEY);
    }
    else if (Response::LOGIN_FAILURE == responseHeader.code)
    {
        /* Receive response payload */
        Response::Response_ClientIDPayload responsePayload;
        _session->read(responsePayload);

        validateClientID(responsePayload.clientID);
    }
    return responseHeader.code;
}

uint16_t ClientLogic::handleRegistration()
{
    /* Send registration request */
    std::cout << "\nSending registration request" << std::endl;
    uint8_t nullID[BYTES_IN_CLIENT_ID] = { 0 };
    Request::Request_ClientNamePayload request(nullID, _version, Request::REGISTER, _clientName);
    _session->write(request);

    /* Receive response header */
    Response::ResponseHeader responseHeader;
    _session->read(responseHeader);
    printResponseHeader(responseHeader.version, responseHeader.code, responseHeader.payloadSize);

    /* Analize response */
    if (Response::REGISTER_SUCCESS == responseHeader.code)
    {
        /* Receive response payload */
        Response::Response_ClientIDPayload responsePayload;
        _session->read(responsePayload);
        _clientID = std::vector<uint8_t>(responsePayload.clientID, responsePayload.clientID + BYTES_IN_CLIENT_ID);
        
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
        meInfoFile.open("me.info");
        meInfoFile << ss.str();
        meInfoFile.close();
    }
    return responseHeader.code;
}

uint16_t ClientLogic::handleKeyExchange()
{
    /* Send key exchange request */
    std::cout << "\nSending key exchange request" << std::endl;
    Request::Request_PublicKeyPayload request(_clientID.data(), _version, Request::KEY_EXCHANGE, _clientName, (uint8_t*)_rsaPrivateWrapper->getPublicKey().c_str());
    _session->write(request);

    /* Receive response header */
    Response::ResponseHeader responseHeader;
    _session->read(responseHeader);
    printResponseHeader(responseHeader.version, responseHeader.code, responseHeader.payloadSize);

    if (Response::PUBLIC_KEY_RECEIVED == responseHeader.code)
    {
        /* Receive response payload */
        Response::Response_EncryptedAesPayload responsePayload;
        _session->read(responsePayload);

        validateClientID(responsePayload.clientID);

        /* Parse encrypted AES key */
        std::string decryptedAesKey = _rsaPrivateWrapper->decrypt((char*)responsePayload.encryptedAesKey, BYTES_IN_ENCRYPTED_AES_KEY);
        _aesWrapper = new AESWrapper((uint8_t*)decryptedAesKey.c_str(), BYTES_IN_AES_KEY);
    }
    return responseHeader.code;
}

uint16_t ClientLogic::handleFileBackup(uint32_t& checksum)
{
    /* Encrypt file before sending */
    const std::string encryptedFilePath = _aesWrapper->encryptFile(_filePath);
    const size_t encryptedFileSize = boost::filesystem::file_size(encryptedFilePath);

    /* Open the encrypted file for reading */
    std::ifstream encryptedFile;
    encryptedFile.exceptions(std::ios::badbit);
    encryptedFile.open(encryptedFilePath, std::ios::binary);

    /* Send file backup request */
    std::cout << "\nSending file backup request" << std::endl;
    Request::Request_FilePayload request(_clientID.data(), _version, Request::BACKUP_FILE, static_cast<uint32_t>(encryptedFileSize), _fileName);
    _session->write(request);

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
        bytesRemaining -= _session->write(buffer, bufferSize);
    }
    encryptedFile.close();
    boost::filesystem::remove(encryptedFilePath);  // remove temp file

    /* Receive response header */
    Response::ResponseHeader responseHeader;
    _session->read(responseHeader);
    printResponseHeader(responseHeader.version, responseHeader.code, responseHeader.payloadSize);

    if (Response::FILE_RECEIVED == responseHeader.code)
    {
        /* Receive response payload */
        Response::Response_CrcPayload responsePayload;
        _session->read(responsePayload);
        checksum = responsePayload.checksum;

        /* Validate arguments */
        validateClientID(responsePayload.clientID);
        validateFileName(responsePayload.fileName);
        if (encryptedFileSize != responsePayload.contentSize)
        {
            throw std::invalid_argument("Content size received from server is incorrect");
        }
    }
    return responseHeader.code;
}

uint16_t ClientLogic::handleValidCRC()
{
    /* Send CRC valid request */
    std::cout << "\nSending valid CRC request" << std::endl;
    Request::Request_FileNamePayload request(_clientID.data(), _version, Request::CRC_VALID, _fileName);
    _session->write(request);

    /* Receive response header */
    Response::ResponseHeader responseHeader;
    _session->read(responseHeader);
    printResponseHeader(responseHeader.version, responseHeader.code, responseHeader.payloadSize);

    if (Response::ACKNOWLEDGE == responseHeader.code)
    {
        /* Receive response payload */
        Response::Response_ClientIDPayload responsePayload;
        _session->read(responsePayload);

        validateClientID(responsePayload.clientID);
    }
    return responseHeader.code;
}

uint16_t ClientLogic::handleInvalidCRC(uint32_t& checksum)
{
    /* Send CRC invalid request */
    std::cout << "\nSending invalid CRC request" << std::endl;
    Request::Request_FileNamePayload request(_clientID.data(), _version, Request::CRC_INVALID_RETRYING, _fileName);
    _session->write(request);

    /* Send the file again */
    return handleFileBackup(checksum);
}

uint16_t ClientLogic::handleAbort()
{
    /* Send abort request */
    std::cout << "\nSending abort request" << std::endl;
    Request::Request_FileNamePayload request(_clientID.data(), _version, Request::CRC_INVALID_ABORTING, _fileName);
    _session->write(request);

    /* Receive response header */
    Response::ResponseHeader responseHeader;
    _session->read(responseHeader);
    printResponseHeader(responseHeader.version, responseHeader.code, responseHeader.payloadSize);

    if (Response::ACKNOWLEDGE == responseHeader.code)
    {
        /* Receive response payload */
        Response::Response_ClientIDPayload responsePayload;
        _session->read(responsePayload);

        validateClientID(responsePayload.clientID);
    }
    return responseHeader.code;
}

inline void ClientLogic::validateClientID(const uint8_t* arg)
{
    if (_clientID != std::vector<uint8_t>(arg, arg + _clientID.size()))
        throw std::invalid_argument("Client ID received from server is incorrect.");
}

inline void ClientLogic::validateFileName(const uint8_t* arg)
{
    if (_fileName != std::string(arg, arg + _fileName.size()))
        throw std::invalid_argument("File name received from server is incorrect");
}