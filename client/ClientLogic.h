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
#include "Session.h"
#include "Protocol.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"

#define VERSION 3

class ClientLogic
{
public:
    /* API Methods */
    ClientLogic();
    ~ClientLogic();
    bool initialize();
    void run();

private:
    /* Request handling related functions */
    uint16_t handleLogin(uint16_t& currRequest);
    uint16_t handleRegistration(uint16_t& currRequest);
    uint16_t handleKeyExchange(uint16_t& currRequest);
    uint16_t handleFileBackup(uint16_t& currRequest, int32_t& retryCount);
    uint16_t handleValidCRC(bool& finished);
    uint16_t handleAbort(bool& finished);

    /* Validation related functions */
    inline void validateClientID(const uint8_t* arg);
    inline void validateFileName(const uint8_t* arg);

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
    Session _session;
};
