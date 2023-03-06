#include "Session.h"
#include "Utilities.h"


Session& Session::getInstance()
{
    static boost::asio::io_context io_context;
    static tcp::socket socket(io_context);
    static tcp::resolver resolver(io_context);

    static Session instance(&io_context, &socket, &resolver);

    return instance;
}


Session::Session(boost::asio::io_context* io, tcp::socket* s, tcp::resolver* r) :
    _io_context(io), _socket(s), _resolver(r)
{
}


void Session::connect(const std::string& host, const std::string& port)
{
    boost::asio::connect(*_socket, _resolver->resolve(host, port));
}


void Session::read(Response::ResponseHeader& response)
{
    boost::asio::read(*_socket, boost::asio::buffer(&response, sizeof(response)));
    if (!Utilities::Endianess::isLittleEndian())
    {
        Utilities::Endianess::changeEndianness(response.version);
        Utilities::Endianess::changeEndianness(response.code);
        Utilities::Endianess::changeEndianness(response.payloadSize);
    }
}


void Session::read(Response::Response_ClientIDPayload& response)
{
    boost::asio::read(*_socket, boost::asio::buffer(&response, sizeof(response)));
}


void Session::read(Response::Response_EncryptedAesPayload& response)
{
    boost::asio::read(*_socket, boost::asio::buffer(&response, sizeof(response)));
}


void Session::read(Response::Response_CrcPayload& response)
{
    boost::asio::read(*_socket, boost::asio::buffer(&response, sizeof(response)));
    if (!Utilities::Endianess::isLittleEndian())
    {
        Utilities::Endianess::changeEndianness(response.contentSize);
        Utilities::Endianess::changeEndianness(response.checksum);
    }
}


size_t Session::write(Request::RequestHeader& request)
{
    if (!Utilities::Endianess::isLittleEndian())
    {
        Utilities::Endianess::changeEndianness(request.version);
        Utilities::Endianess::changeEndianness(request.code);
        Utilities::Endianess::changeEndianness(request.payloadSize);
    }
    return boost::asio::write(*_socket, boost::asio::buffer(&request, sizeof(request)));
}


size_t Session::write(Request::Request_ClientNamePayload& request)
{
    return boost::asio::write(*_socket, boost::asio::buffer(&request, sizeof(request)));
}


size_t Session::write(Request::Request_FileNamePayload& request)
{
    return boost::asio::write(*_socket, boost::asio::buffer(&request, sizeof(request)));
}


size_t Session::write(Request::Request_PublicKeyPayload& request)
{
    return boost::asio::write(*_socket, boost::asio::buffer(&request, sizeof(request)));
}


size_t Session::write(Request::Request_FilePayload& request)
{
    if (!Utilities::Endianess::isLittleEndian())
    {
        Utilities::Endianess::changeEndianness(request.contentSize);
    }
    return boost::asio::write(*_socket, boost::asio::buffer(&request, sizeof(request)));
}


size_t Session::write(const char* buffer, const size_t bufferSize)
{
    return boost::asio::write(*_socket, boost::asio::buffer(buffer, bufferSize));
}
