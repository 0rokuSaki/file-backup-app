#include "Protocol.h"


bool isLittleEndian()
{
	static const int num = 1;
	return (*(char*)&num == 1) ? true : false;
}


template <typename uintX_t>
void changeEndianness(uintX_t& src)
{
	uint8_t buffer[sizeof(uintX_t)] = { 0 };
	memcpy(buffer, &src, sizeof(uintX_t));
	std::reverse(buffer, buffer + sizeof(uintX_t));
	memcpy(&src, buffer, sizeof(uintX_t));
}


namespace REQUEST
{
	void packRequestHeader(
		RequestHeader& request,
		const uint8_t* clientID,
		const uint8_t version,
		const uint16_t code,
		const uint32_t payloadSize
	)
	{
		memcpy(request.clientID, clientID, BYTES_IN_CLIENT_ID);
		request.version = version;
		request.code = code;
		request.payloadSize = payloadSize;
		if (!isLittleEndian())
		{
			changeEndianness(request.version);
			changeEndianness(request.code);
			changeEndianness(request.payloadSize);
		}
	}


	void packRequest_ClientNamePayload(
		Request_ClientNamePayload& request,
		const uint8_t* clientID,
		const uint8_t version,
		const uint16_t code,
		const uint32_t payloadSize,
		const uint8_t* clientName
	)
	{
		packRequestHeader(request, clientID, version, code, payloadSize);
		memcpy(request.clientName, clientName, BYTES_IN_CLIENT_NAME);
	}


	void packRequest_FileNamePayload(
		Request_FileNamePayload& request,
		const uint8_t* clientID,
		const uint8_t version,
		const uint16_t code,
		const uint32_t payloadSize,
		const uint8_t* fileName
	)
	{
		packRequestHeader(request, clientID, version, code, payloadSize);
		memcpy(request.fileName, fileName, BYTES_IN_FILE_NAME);
	}


	void packRequest_PublicKeyPayload(
		Request_PublicKeyPayload& request,
		const uint8_t* clientID,
		const uint8_t version,
		const uint16_t code,
		const uint32_t payloadSize,
		const uint8_t* clientName,
		const uint8_t* publicKey
	)
	{
		packRequestHeader(request, clientID, version, code, payloadSize);
		memcpy(request.clientName, clientName, BYTES_IN_CLIENT_NAME);
		memcpy(request.publicKey, publicKey, BYTES_IN_PUBLIC_KEY);
	}


	void packRequest_FilePayload(
		Request_FilePayload& request,
		const uint8_t* clientID,
		const uint8_t version,
		const uint16_t code,
		const uint32_t payloadSize,
		const uint32_t contentSize,
		const uint8_t* fileName
	)
	{
		packRequestHeader(request, clientID, version, code, payloadSize);
		request.contentSize = contentSize;
		if (!isLittleEndian())
		{
			changeEndianness(request.contentSize);
		}
		memcpy(request.fileName, fileName, BYTES_IN_FILE_NAME);
	}
}

namespace RESPONSE
{
	void unpackResponseHeader(
		ResponseHeader& response,
		uint8_t& version,
		uint16_t& code,
		uint32_t& payloadSize
	)
	{
		version = response.version;
		code = response.code;
		payloadSize = response.payloadSize;
		if (!isLittleEndian())
		{
			changeEndianness(version);
			changeEndianness(code);
			changeEndianness(payloadSize);
		}
	}


	void unpackResponse_UuidPayload(
		Response_UuidPayload& response,
		uint8_t& version,
		uint16_t& code,
		uint32_t& payloadSize,
		std::vector<uint8_t>& clientID
	)
	{
		unpackResponseHeader(response, version, code, payloadSize);
		clientID = std::vector<uint8_t>(response.clientID, response.clientID + BYTES_IN_CLIENT_ID);
	}


	void unpackResponse_EncryptedAesPayload(
		Response_EncryptedAesPayload& response,
		uint8_t& version,
		uint16_t& code,
		uint32_t& payloadSize,
		std::vector<uint8_t>& clientID,
		std::vector<uint8_t>& encryptedAesKey
	)
	{
		unpackResponseHeader(response, version, code, payloadSize);
		clientID = std::vector<uint8_t>(response.clientID, response.clientID + BYTES_IN_CLIENT_ID);
		encryptedAesKey = std::vector<uint8_t>(response.encryptedAesKey, response.encryptedAesKey + BYTES_IN_ENCRYPTED_AES_KEY);
	}


	void unpackResponse_CrcPayload(
		Response_CrcPayload& response,
		uint8_t& version,
		uint16_t& code,
		uint32_t& payloadSize,
		std::vector<uint8_t>& clientID,
		uint32_t& contentSize,
		std::string& fileName,
		uint32_t& checkSum
	)
	{
		unpackResponseHeader(response, version, code, payloadSize);
		clientID = std::vector<uint8_t>(response.clientID, response.clientID + BYTES_IN_CLIENT_ID);
		contentSize = response.contentSize;
		fileName = std::string(response.fileName, response.fileName + BYTES_IN_FILE_NAME);
		checkSum = response.checkSum;
		if (!isLittleEndian())
		{
			changeEndianness(contentSize);
			changeEndianness(checkSum);
		}
	}
}