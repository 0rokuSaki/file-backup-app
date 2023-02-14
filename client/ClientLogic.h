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
    ClientLogic(const std::string& rootPath);

    ~ClientLogic();

    void run();

private:
    /* Initialization related functions */
    bool parseTransferInfo();
    bool parseMeInfo();

    /* Session related functions */
    Response::ResponseCode handleLogin(tcp::socket& s);
    Response::ResponseCode handleRegistration(tcp::socket& s);
    Response::ResponseCode handleKeyExchange(tcp::socket& s);
    Response::ResponseCode handleFileBackup(tcp::socket& s, const std::string& filePath);
    Response::ResponseCode handleValidCRC(tcp::socket& s);
    Response::ResponseCode handleInvalidCRC(tcp::socket& s);
    Response::ResponseCode handleAbort(tcp::socket& s);

    
    static const size_t _maxClientNameLength = 100;
    static const uint8_t _version = 3;

    /* Client info details related variables */
    std::string _clientName;
    std::vector<uint8_t> _clientID;

    /* File related variables */
    std::string _rootPath;
    std::string _fileName;
    uint32_t _checksum;

    /* Encryption relatedd variables */
    RSAPrivateWrapper* _rsaPrivateWrapper;
    AESWrapper* _aesWrapper;

    /* I/O related variables */
    std::string _hostAddress;
    std::string _hostPort;
};

