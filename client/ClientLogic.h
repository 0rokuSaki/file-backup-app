#pragma once
#include "Protocol.h"

#include <boost/asio.hpp>

#include <string>
#include <vector>


using boost::asio::ip::tcp;

class ClientLogic
{
public:
    ClientLogic(const std::string& rootPath);

    void run();

private:
    /* Initialization related functions */
    bool parseTransferInfo();
    bool parseMeInfo();

    /* Session related functions */
    Response::ResponseCode handleLogin(tcp::socket& s);
    Response::ResponseCode handleRegistration(tcp::socket& s);
    Response::ResponseCode handleKeyExchange(tcp::socket& s);
    Response::ResponseCode handleFileBackup(tcp::socket& s);
    Response::ResponseCode handleValidCRC(tcp::socket& s);
    Response::ResponseCode handleInvalidCRC(tcp::socket& s);
    Response::ResponseCode handleAbort(tcp::socket& s);
    
    /* For file handling */
    std::string _rootPath;

    /* Client details related variables */
    static const size_t MAX_CLIENT_NAME_SIZE = 100;
    std::string _fileName;
    std::string _clientName;
    std::string _privateKeyBase64;
    std::vector<uint8_t> _clientID;

    /* I/O related variables */
    std::string _hostAddress;
    std::string _hostPort;
};

