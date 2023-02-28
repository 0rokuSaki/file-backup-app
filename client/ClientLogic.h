#pragma once
#include "Protocol.h"

#include "RSAWrapper.h"
#include "AESWrapper.h"

#include <boost/asio.hpp>

#include <string>
#include <vector>


using boost::asio::ip::tcp;

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

    /* Session related functions */
    uint16_t handleLogin(tcp::socket& s);
    uint16_t handleRegistration(tcp::socket& s);
    uint16_t handleKeyExchange(tcp::socket& s);
    uint16_t handleFileBackup(tcp::socket& s, uint32_t& checksum);
    uint16_t handleValidCRC(tcp::socket& s);
    uint16_t handleInvalidCRC(tcp::socket& s, uint32_t& checksum);
    uint16_t handleAbort(tcp::socket& s);

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
};

