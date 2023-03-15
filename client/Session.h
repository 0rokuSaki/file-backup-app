#pragma once
#include <boost/asio.hpp>
#include <string>
#include <vector>
#include "Protocol.h"

using boost::asio::ip::tcp;

class Session
{
public:
    /* API Methods */
    Session();
    ~Session();
    void connect(const std::string& host, const std::string& port);
    void read(Response::ResponseHeader& response);
    void read(Response::Response_ClientIDPayload& response);
    void read(Response::Response_EncryptedAesPayload& response);
    void read(Response::Response_CrcPayload& response);
    size_t write(Request::RequestHeader& request);
    size_t write(Request::Request_ClientNamePayload& request);
    size_t write(Request::Request_FileNamePayload& request);
    size_t write(Request::Request_PublicKeyPayload& request);
    size_t write(Request::Request_FilePayload& request);
    size_t write(const char* buffer, const size_t bufferSize);

private:
    Session(const Session&);

    /* Instance variables */
    boost::asio::io_context* _io_context;
    tcp::socket* _socket;
    tcp::resolver* _resolver;
};

