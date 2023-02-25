#include "Protocol.h"
#include "Utilities.h"
#include <cstring>


namespace Request
{
	void RequestHeader::pack(
		const uint8_t* clientID,
		const uint8_t version,
		const uint16_t code,
		const uint32_t payloadSize
	)
	{
		memcpy(this->clientID, clientID, BYTES_IN_CLIENT_ID);
		this->version = version;
		this->code = code;
		this->payloadSize = payloadSize;
		if (!Utilities::Endianess::isLittleEndian())
		{
			Utilities::Endianess::changeEndianness(this->version);
			Utilities::Endianess::changeEndianness(this->code);
			Utilities::Endianess::changeEndianness(this->payloadSize);
		}
	}


	void Request_ClientNamePayload::pack(
		const uint8_t* clientID,
		const uint8_t version,
		const uint16_t code,
		const std::string& clientName
	)
	{
		RequestHeader::pack(clientID, version, code, BYTES_IN_CLIENT_NAME);
		memcpy(this->clientName, clientName.c_str(), clientName.size());
	}


	void Request_FileNamePayload::pack(
		const uint8_t* clientID,
		const uint8_t version,
		const uint16_t code,
		const std::string& fileName
	)
	{
		RequestHeader::pack(clientID, version, code, BYTES_IN_FILE_NAME);
		memcpy(this->fileName, fileName.c_str(), fileName.size());
	}


	void Request_PublicKeyPayload::pack(
		const uint8_t* clientID,
		const uint8_t version,
		const uint16_t code,
		const std::string& clientName,
		const uint8_t* publicKey
	)
	{
		RequestHeader::pack(clientID, version, code, BYTES_IN_CLIENT_NAME + BYTES_IN_PUBLIC_KEY);
		memcpy(this->clientName, clientName.c_str(), clientName.size());
		memcpy(this->publicKey, publicKey, BYTES_IN_PUBLIC_KEY);
	}


	void Request_FilePayload::pack(
		const uint8_t* clientID,
		const uint8_t version,
		const uint16_t code,
		const uint32_t contentSize,
		const std::string& fileName
	)
	{
		RequestHeader::pack(clientID, version, code, BYTES_IN_CONTENT_SIZE + BYTES_IN_FILE_NAME + contentSize);
		this->contentSize = contentSize;
		if (!Utilities::Endianess::isLittleEndian())
		{
			Utilities::Endianess::changeEndianness(this->contentSize);
		}
		memcpy(this->fileName, fileName.c_str(), fileName.size());
	}
}

namespace Response
{
	void ResponseHeader::unpack(
		uint8_t& version,
		uint16_t& code,
		uint32_t& payloadSize
	)
	{
		version = this->version;
		code = this->code;
		payloadSize = this->payloadSize;
		if (!Utilities::Endianess::isLittleEndian())
		{
			Utilities::Endianess::changeEndianness(version);
			Utilities::Endianess::changeEndianness(code);
			Utilities::Endianess::changeEndianness(payloadSize);
		}
	}


	void Response_ClientIDPayload::unpack(std::vector<uint8_t>& clientID)
	{
		clientID = std::vector<uint8_t>(this->clientID, this->clientID + BYTES_IN_CLIENT_ID);
	}


	void Response_EncryptedAesPayload::unpack(std::vector<uint8_t>& clientID, std::vector<uint8_t>& encryptedAesKey)
	{
		clientID = std::vector<uint8_t>(this->clientID, this->clientID + BYTES_IN_CLIENT_ID);
		encryptedAesKey = std::vector<uint8_t>(this->encryptedAesKey, this->encryptedAesKey + BYTES_IN_ENCRYPTED_AES_KEY);
	}


	void Response_CrcPayload::unpack(std::vector<uint8_t>& clientID, uint32_t& contentSize, std::string& fileName, uint32_t& checksum)
	{
		clientID = std::vector<uint8_t>(this->clientID, this->clientID + BYTES_IN_CLIENT_ID);
		contentSize = this->contentSize;
		this->fileName[BYTES_IN_FILE_NAME - 1] = '\0';  // Make sure it's a null-terminated string
		fileName = std::string(this->fileName, this->fileName + std::strlen((char*)this->fileName));
		checksum = this->checksum;
		if (!Utilities::Endianess::isLittleEndian())
		{
			Utilities::Endianess::changeEndianness(contentSize);
			Utilities::Endianess::changeEndianness(checksum);
		}
	}
}