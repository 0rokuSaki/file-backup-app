/*****************************************************************//**
 * \file   ClientLogic.h
 * \brief  Class declaration for ClientLogic.
 * 
 * \author aaron
 * \date   March 2023
 *********************************************************************/

#pragma once
#include <string>
#include <vector>
#include "Protocol.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"


class Session;  // Forward declaration


class ClientLogic
{
public:
    ClientLogic();

    ~ClientLogic();

    bool initialize();

    bool run();

private:
    /* Initialization related functions */
    bool parseTransferInfo(std::stringstream& errorMessage);
    bool parseMeInfo(std::stringstream& errorMessage);

    /* Request handling related functions */
    uint16_t handleLogin();
    uint16_t handleRegistration();
    uint16_t handleKeyExchange();
    uint16_t handleFileBackup(uint32_t& checksum);
    uint16_t handleValidCRC();
    uint16_t handleInvalidCRC(uint32_t& checksum);
    uint16_t handleAbort();

    /* Validation related functions */
    inline void validateClientID(const uint8_t* arg);
    inline void validateFileName(const uint8_t* arg);

    /* Various constants */
    static const size_t _maxTransferSize = UINT32_MAX - BYTES_IN_CONTENT_SIZE - BYTES_IN_FILE_NAME;
    static const size_t _maxClientNameLength = 100;
    static const uint8_t _version = 3;

    /* Client info details related variables */
    bool _needToRegister;
    std::string _clientName;
    std::vector<uint8_t> _clientID;

    /* File related variables */
    std::string _filePath;
    std::string _fileName;
    uint32_t _checksum;

    /* Encryption relatedd variables */
    RSAPrivateWrapper* _rsaPrivateWrapper;
    AESWrapper* _aesWrapper;

    /* I/O related variables */
    std::string _hostAddress;
    std::string _hostPort;
    Session* _session;
};
