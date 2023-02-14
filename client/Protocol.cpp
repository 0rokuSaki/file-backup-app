#include "Protocol.h"
#include "Utilities.h"


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
		const uint32_t payloadSize,
		const uint8_t* clientName
	)
	{
		RequestHeader::pack(clientID, version, code, payloadSize);
		memcpy(this->clientName, clientName, BYTES_IN_CLIENT_NAME);
	}


	void Request_FileNamePayload::pack(
		const uint8_t* clientID,
		const uint8_t version,
		const uint16_t code,
		const uint32_t payloadSize,
		const uint8_t* fileName
	)
	{
		RequestHeader::pack(clientID, version, code, payloadSize);
		memcpy(this->fileName, fileName, BYTES_IN_FILE_NAME);
	}


	void Request_PublicKeyPayload::pack(
		const uint8_t* clientID,
		const uint8_t version,
		const uint16_t code,
		const uint32_t payloadSize,
		const uint8_t* clientName,
		const uint8_t* publicKey
	)
	{
		RequestHeader::pack(clientID, version, code, payloadSize);
		memcpy(this->clientName, clientName, BYTES_IN_CLIENT_NAME);
		memcpy(this->publicKey, publicKey, BYTES_IN_PUBLIC_KEY);
	}


	void Request_FilePayload::pack(
		const uint8_t* clientID,
		const uint8_t version,
		const uint16_t code,
		const uint32_t payloadSize,
		const uint32_t contentSize,
		const uint8_t* fileName
	)
	{
		RequestHeader::pack(clientID, version, code, payloadSize);
		this->contentSize = contentSize;
		if (!Utilities::Endianess::isLittleEndian())
		{
			Utilities::Endianess::changeEndianness(this->contentSize);
		}
		memcpy(this->fileName, fileName, BYTES_IN_FILE_NAME);
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


	void Response_UuidPayload::unpack(
		uint8_t& version,
		uint16_t& code,
		uint32_t& payloadSize,
		std::vector<uint8_t>& clientID
	)
	{
		ResponseHeader::unpack(version, code, payloadSize);
		clientID = std::vector<uint8_t>(this->clientID, this->clientID + BYTES_IN_CLIENT_ID);
	}


	void Response_EncryptedAesPayload::unpack(
		uint8_t& version,
		uint16_t& code,
		uint32_t& payloadSize,
		std::vector<uint8_t>& clientID,
		std::vector<uint8_t>& encryptedAesKey
	)
	{
		ResponseHeader::unpack(version, code, payloadSize);
		clientID = std::vector<uint8_t>(this->clientID, this->clientID + BYTES_IN_CLIENT_ID);
		encryptedAesKey = std::vector<uint8_t>(this->encryptedAesKey, this->encryptedAesKey + BYTES_IN_ENCRYPTED_AES_KEY);
	}


	void Response_CrcPayload::unpack(
		uint8_t& version,
		uint16_t& code,
		uint32_t& payloadSize,
		std::vector<uint8_t>& clientID,
		uint32_t& contentSize,
		std::string& fileName,
		uint32_t& checkSum
	)
	{
		ResponseHeader::unpack(version, code, payloadSize);
		clientID = std::vector<uint8_t>(this->clientID, this->clientID + BYTES_IN_CLIENT_ID);
		contentSize = this->contentSize;
		fileName = std::string(this->fileName, this->fileName + BYTES_IN_FILE_NAME);
		checkSum = this->checkSum;
		if (!Utilities::Endianess::isLittleEndian())
		{
			Utilities::Endianess::changeEndianness(contentSize);
			Utilities::Endianess::changeEndianness(checkSum);
		}
	}
}