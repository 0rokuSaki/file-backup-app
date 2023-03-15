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

#include "Base64Wrapper.h"
#include "ClientLogic.h"
#include "Utilities.h"
#include "Parser.h"

#define NUMBER_OF_RETRIES 3


/* Prints response header */
void printResponseHeader(const uint8_t serverVersion, const uint16_t responseCode, const uint32_t payloadSize)
{
    std::cout << "Response received:\n" <<
        "(1) Server version = " << static_cast<int>(serverVersion) << "\n" <<
        "(2) Response code = " << responseCode << "\n" <<
        "(3) Payload size = " << payloadSize << std::endl;
}


ClientLogic::ClientLogic() : _checksum(0), _needToRegister(false),
    _rsaPrivateWrapper(nullptr), _aesWrapper(nullptr)
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
    std::stringstream errMsg;
    Parser parser;
    /* Parse transfer.info file */
    if (!parser.parseTransferInfo(errMsg))
    {
        std::cerr << "Error parsing transfer.info: " << errMsg.str() << std::endl;
        return false;
    }

    _hostAddress = parser.getHostAddress();
    _hostPort = parser.getHostPort();
    _clientName = parser.getClientName();
    _fileName = parser.getFileName();
    _filePath = parser.getFilePath();

    std::cout << "Success parsing transfer.info with the following parameters:\n"
        "(1) Host address: " << _hostAddress << "\n"
        "(2) Host port: " << _hostPort << "\n"
        "(3) Client name: " << _clientName << "\n"
        "(4) File name: " << _fileName << std::endl;

    /* Parse me.info file */
    if (boost::filesystem::exists("me.info"))
    {
        if (!parser.parseMeInfo(errMsg))
        {
            std::cerr << "Error parsing me.info: " << errMsg.str() << std::endl;
            return false;
        }

        _clientID = parser.getClientID();
        _rsaPrivateWrapper = new RSAPrivateWrapper(Base64Wrapper::decode(parser.getPrivateKeyBase64()));

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
    constexpr size_t maxTransferSize = UINT32_MAX - BYTES_IN_CONTENT_SIZE - BYTES_IN_FILE_NAME;
    if (encryptedFileSize > maxTransferSize)
    {
        std::cerr << "File is too large to transfer (file size = " << fileSize << ", max size = " << maxTransferSize << ")";
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


void ClientLogic::run()
{
    try
    {
        std::cout << "Connecting to server " << _hostAddress << ":" << _hostPort << std::endl;
        _session.connect(_hostAddress, _hostPort);
        std::cout << "Successfully connected to server" << std::endl;

        /* Client makes requests untill finished */
        uint16_t currRequest = _needToRegister ? Request::REGISTER : Request::LOGIN;
        bool finished = false;
        while (!finished)
        {
            int32_t retryCount;
            for (retryCount = 1; retryCount <= NUMBER_OF_RETRIES; ++retryCount)
            {
                const uint16_t prevRequest = currRequest;
                uint16_t rc;
                switch (currRequest)
                {
                case Request::REGISTER:
                    rc = handleRegistration(currRequest);
                    break;
                case Request::LOGIN:
                    rc = handleLogin(currRequest);
                    break;
                case Request::KEY_EXCHANGE:
                    rc = handleKeyExchange(currRequest);
                    break;
                case Request::BACKUP_FILE:
                    rc = handleFileBackup(currRequest, retryCount);
                    break;
                case Request::CRC_VALID:
                    rc = handleValidCRC(finished);
                    break;
                case Request::CRC_INVALID_ABORTING:
                    rc = handleAbort(finished);
                    break;
                default:  // Should never get here
                    throw std::runtime_error("Fatal error - invalid request code");
                }

                if (finished || prevRequest != currRequest)
                {  // Request handled successfully - continue to next step
                    break;
                }
                else if (Response::GENERAL_FAILURE == rc)
                {  // Error on server
                    std::cout << "Server responded with an error, retrying... (retry count = " << retryCount << ")" << std::endl;
                }
                else if (rc <= Response::FIRST_OF_RESPONSE || rc >= Response::LAST_OF_RESPONSE)
                {  // Response code is invalid - server is sending nonsense to client
                    throw std::runtime_error("Fatal error - server's response does not align with protocol");
                }
            }  // End of for loop
            if (retryCount > NUMBER_OF_RETRIES)
            {
                throw std::runtime_error("Fatal error - maximum number of retries reached (request code = " + std::to_string(currRequest) + ")");
            }
        }  // End of while loop
    }
    catch (const std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
}


uint16_t ClientLogic::handleLogin(uint16_t& currRequest)
{
    /* Send login request */
    std::cout << "\nSending login request" << std::endl;
    Request::Request_ClientNamePayload request(_clientID.data(), VERSION, Request::LOGIN, _clientName);
    _session.write(request);

    /* Receive response header */
    Response::ResponseHeader responseHeader;
    _session.read(responseHeader);
    printResponseHeader(responseHeader.version, responseHeader.code, responseHeader.payloadSize);

    /* Analize response */
    if (Response::LOGIN_SUCCESS == responseHeader.code)
    {
        /* Receive response payload */
        Response::Response_EncryptedAesPayload responsePayload;
        _session.read(responsePayload);

        validateClientID(responsePayload.clientID);

        /* Parse encrypted AES key */
        std::string decryptedAesKey = _rsaPrivateWrapper->decrypt((char*)responsePayload.encryptedAesKey, BYTES_IN_ENCRYPTED_AES_KEY);
        _aesWrapper = new AESWrapper((uint8_t*)decryptedAesKey.c_str(), BYTES_IN_AES_KEY);

        std::cout << "Successfully logged in to server" << std::endl;
        currRequest = Request::BACKUP_FILE;
    }
    else if (Response::LOGIN_FAILURE == responseHeader.code)
    {
        /* Receive response payload */
        Response::Response_ClientIDPayload responsePayload;
        _session.read(responsePayload);

        validateClientID(responsePayload.clientID);

        std::cout << "Failed to login to server, attempting to register" << std::endl;
        currRequest = Request::REGISTER;
    }
    return responseHeader.code;
}


uint16_t ClientLogic::handleRegistration(uint16_t& currRequest)
{
    /* Send registration request */
    std::cout << "\nSending registration request" << std::endl;
    uint8_t nullID[BYTES_IN_CLIENT_ID] = { 0 };
    Request::Request_ClientNamePayload request(nullID, VERSION, Request::REGISTER, _clientName);
    _session.write(request);

    /* Receive response header */
    Response::ResponseHeader responseHeader;
    _session.read(responseHeader);
    printResponseHeader(responseHeader.version, responseHeader.code, responseHeader.payloadSize);

    /* Analize response */
    if (Response::REGISTER_SUCCESS == responseHeader.code)
    {
        /* Receive response payload */
        Response::Response_ClientIDPayload responsePayload;
        _session.read(responsePayload);
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

        std::cout << "Successfully registered to server" << std::endl;
        currRequest = Request::KEY_EXCHANGE;
    }
    else if (Response::REGISTER_FAILURE == responseHeader.code)
    {
        throw std::runtime_error("Failed to register to server");
    }
    return responseHeader.code;
}


uint16_t ClientLogic::handleKeyExchange(uint16_t& currRequest)
{
    /* Send key exchange request */
    std::cout << "\nSending key exchange request" << std::endl;
    Request::Request_PublicKeyPayload request(_clientID.data(), VERSION, Request::KEY_EXCHANGE, _clientName, (uint8_t*)_rsaPrivateWrapper->getPublicKey().c_str());
    _session.write(request);

    /* Receive response header */
    Response::ResponseHeader responseHeader;
    _session.read(responseHeader);
    printResponseHeader(responseHeader.version, responseHeader.code, responseHeader.payloadSize);

    if (Response::PUBLIC_KEY_RECEIVED == responseHeader.code)
    {
        /* Receive response payload */
        Response::Response_EncryptedAesPayload responsePayload;
        _session.read(responsePayload);

        validateClientID(responsePayload.clientID);

        /* Parse encrypted AES key */
        std::string decryptedAesKey = _rsaPrivateWrapper->decrypt((char*)responsePayload.encryptedAesKey, BYTES_IN_ENCRYPTED_AES_KEY);
        _aesWrapper = new AESWrapper((uint8_t*)decryptedAesKey.c_str(), BYTES_IN_AES_KEY);

        std::cout << "Successfully exchanged keys with server" << std::endl;
        currRequest = Request::BACKUP_FILE;
    }
    return responseHeader.code;
}


uint16_t ClientLogic::handleFileBackup(uint16_t& currRequest, int32_t& retryCount)
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
    Request::Request_FilePayload request(_clientID.data(), VERSION, Request::BACKUP_FILE, static_cast<uint32_t>(encryptedFileSize), _fileName);
    _session.write(request);

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
        bytesRemaining -= _session.write(buffer, bufferSize);
    }
    encryptedFile.close();
    boost::filesystem::remove(encryptedFilePath);  // remove temp file

    /* Receive response header */
    Response::ResponseHeader responseHeader;
    _session.read(responseHeader);
    printResponseHeader(responseHeader.version, responseHeader.code, responseHeader.payloadSize);

    if (Response::FILE_RECEIVED == responseHeader.code)
    {
        /* Receive response payload */
        Response::Response_CrcPayload responsePayload;
        _session.read(responsePayload);

        /* Validate arguments */
        validateClientID(responsePayload.clientID);
        validateFileName(responsePayload.fileName);
        if (encryptedFileSize != responsePayload.contentSize)
        {
            throw std::runtime_error("Content size received from server is incorrect");
        }

        if (_checksum == responsePayload.checksum)
        {
            std::cout << "File transfer successful - CRC is valid" << std::endl;
            currRequest = Request::CRC_VALID;
        }
        else if (retryCount < NUMBER_OF_RETRIES)
        {
            std::cout << "File transfer failed - CRC is invalid. Retrying... (retry count = " << retryCount << ")" << std::endl;
            /* Send CRC invalid request */
            std::cout << "\nSending invalid CRC request" << std::endl;
            Request::Request_FileNamePayload request(_clientID.data(), VERSION, Request::CRC_INVALID_RETRYING, _fileName);
            _session.write(request);
        }
        else  // Maximum number of retries reched
        {
            std::cout << "File transfer failed - CRC is invalid. Aborting... (retry count = " << retryCount << ")" << std::endl;
            currRequest = Request::CRC_INVALID_ABORTING;
            retryCount = 1;
        }
    }
    return responseHeader.code;
}


uint16_t ClientLogic::handleValidCRC(bool& finished)
{
    /* Send CRC valid request */
    std::cout << "\nSending valid CRC request" << std::endl;
    Request::Request_FileNamePayload request(_clientID.data(), VERSION, Request::CRC_VALID, _fileName);
    _session.write(request);

    /* Receive response header */
    Response::ResponseHeader responseHeader;
    _session.read(responseHeader);
    printResponseHeader(responseHeader.version, responseHeader.code, responseHeader.payloadSize);

    if (Response::ACKNOWLEDGE == responseHeader.code)
    {
        /* Receive response payload */
        Response::Response_ClientIDPayload responsePayload;
        _session.read(responsePayload);
        validateClientID(responsePayload.clientID);
        std::cout << "Successfully verified CRC" << std::endl;
        finished = true;
    }
    return responseHeader.code;
}


uint16_t ClientLogic::handleAbort(bool& finished)
{
    /* Send abort request */
    std::cout << "\nSending abort request" << std::endl;
    Request::Request_FileNamePayload request(_clientID.data(), VERSION, Request::CRC_INVALID_ABORTING, _fileName);
    _session.write(request);

    /* Receive response header */
    Response::ResponseHeader responseHeader;
    _session.read(responseHeader);
    printResponseHeader(responseHeader.version, responseHeader.code, responseHeader.payloadSize);

    if (Response::ACKNOWLEDGE == responseHeader.code)
    {
        /* Receive response payload */
        Response::Response_ClientIDPayload responsePayload;
        _session.read(responsePayload);
        validateClientID(responsePayload.clientID);
        finished = true;
    }
    return responseHeader.code;
}


inline void ClientLogic::validateClientID(const uint8_t* arg)
{
    if (_clientID != std::vector<uint8_t>(arg, arg + _clientID.size()))
        throw std::runtime_error("Client ID received from server is incorrect.");
}


inline void ClientLogic::validateFileName(const uint8_t* arg)
{
    if (_fileName != std::string(arg, arg + _fileName.size()))
        throw std::runtime_error("File name received from server is incorrect");
}