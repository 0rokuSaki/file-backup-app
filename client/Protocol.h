/*****************************************************************//**
 * \file   Protocol.h
 * \brief  Protocol definitions for the project.
 * 
 * \author aaron
 * \date   March 2023
 *********************************************************************/
#pragma once
#include <vector>
#include <string>

#define BYTES_IN_VERSION              1
#define BYTES_IN_REQ_RES_CODE         2
#define BYTES_IN_PAYLOAD_SIZE         4
#define BYTES_IN_CONTENT_SIZE         4
#define BYTES_IN_CLIENT_ID           16
#define BYTES_IN_AES_KEY             16
#define BYTES_IN_ENCRYPTED_AES_KEY    8 * BYTES_IN_AES_KEY
#define BYTES_IN_PUBLIC_KEY         160
#define BYTES_IN_CLIENT_NAME        255 // Including '\0' terminator
#define BYTES_IN_FILE_NAME          255 // Including '\0' terminator

#define MAX_CLIENT_NAME_LEN         100 // Client name length constraint


namespace Request
{
	/* Available request codes */
	enum RequestCode
	{
		REGISTER =             1100,
		KEY_EXCHANGE =         1101,
		LOGIN =                1102,
		BACKUP_FILE =          1103,
		CRC_VALID =            1104,
		CRC_INVALID_RETRYING = 1105,
		CRC_INVALID_ABORTING = 1106
	};

	/* Request structures */
#pragma pack(push, 1)
	struct RequestHeader
	{
		uint8_t clientID[BYTES_IN_CLIENT_ID];
		uint8_t version;
		uint16_t code;
		uint32_t payloadSize;

		RequestHeader(
			const uint8_t* clientID,
			const uint8_t version,
			const uint16_t code,
			const uint32_t payloadSize
		) : version(version), code(code), payloadSize(payloadSize)
		{
			memset(this->clientID, 0, BYTES_IN_CLIENT_ID);
			memcpy(this->clientID, clientID, BYTES_IN_CLIENT_ID);
		}
	};

	struct Request_ClientNamePayload : public RequestHeader
	{
		uint8_t clientName[BYTES_IN_CLIENT_NAME];

		Request_ClientNamePayload(
			const uint8_t* clientID,
			const uint8_t version,
			const uint16_t code,
			const std::string& clientName
		) : RequestHeader(clientID, version, code, BYTES_IN_CLIENT_NAME)
		{
			memset(this->clientName, 0, BYTES_IN_CLIENT_NAME);
			memcpy(this->clientName, clientName.c_str(), clientName.size());
		}
	};

	struct Request_FileNamePayload : public RequestHeader
	{
		uint8_t fileName[BYTES_IN_FILE_NAME];

		Request_FileNamePayload(
			const uint8_t* clientID,
			const uint8_t version,
			const uint16_t code,
			const std::string& fileName
		) : RequestHeader(clientID, version, code, BYTES_IN_FILE_NAME)
		{
			memset(this->fileName, 0, BYTES_IN_FILE_NAME);
			memcpy(this->fileName, fileName.c_str(), fileName.size());
		}
	};

	struct Request_PublicKeyPayload : public RequestHeader
	{
		uint8_t clientName[BYTES_IN_CLIENT_NAME];
		uint8_t publicKey[BYTES_IN_PUBLIC_KEY];

		Request_PublicKeyPayload(
			const uint8_t* clientID,
			const uint8_t version,
			const uint16_t code,
			const std::string& clientName,
			const uint8_t* publicKey
		) : RequestHeader(clientID, version, code, BYTES_IN_CLIENT_NAME + BYTES_IN_PUBLIC_KEY)
		{
			memset(this->clientName, 0, BYTES_IN_CLIENT_NAME);
			memset(this->publicKey, 0, BYTES_IN_PUBLIC_KEY);
			memcpy(this->clientName, clientName.c_str(), clientName.size());
			memcpy(this->publicKey, publicKey, BYTES_IN_PUBLIC_KEY);
		}
	};

	struct Request_FilePayload : public RequestHeader
	{
		uint32_t contentSize;
		uint8_t fileName[BYTES_IN_FILE_NAME];

		Request_FilePayload(
			const uint8_t* clientID,
			const uint8_t version,
			const uint16_t code,
			const uint32_t contentSize,
			const std::string& fileName
		) : RequestHeader(clientID, version, code, BYTES_IN_CONTENT_SIZE + BYTES_IN_FILE_NAME + contentSize), contentSize(contentSize)
		{
			memset(this->fileName, 0, BYTES_IN_FILE_NAME);
			memcpy(this->fileName, fileName.c_str(), fileName.size());
		}
	};
#pragma pack(pop)
}


namespace Response
{
	/* Available response codes */
	enum ResponseCode
	{
		FIRST_OF_RESPONSE =    2099,  // Used for validation
		REGISTER_SUCCESS =     2100,
		REGISTER_FAILURE =     2101,
		PUBLIC_KEY_RECEIVED =  2102,
		FILE_RECEIVED =        2103,
		ACKNOWLEDGE =          2104,
		LOGIN_SUCCESS =        2105,
		LOGIN_FAILURE =        2106,
		GENERAL_FAILURE =      2107,
		LAST_OF_RESPONSE =     2108   // Used for validation
	};

	/* Response structures */
#pragma pack(push, 1)
	struct ResponseHeader
	{
		uint8_t version;
		uint16_t code;
		uint32_t payloadSize;

		ResponseHeader() : version(0), code(0), payloadSize(0) {}
	};

	struct Response_ClientIDPayload
	{
		uint8_t clientID[BYTES_IN_CLIENT_ID];

		Response_ClientIDPayload()
		{
			memset(clientID, 0, BYTES_IN_CLIENT_ID);
		}
	};

	struct Response_EncryptedAesPayload
	{
		uint8_t clientID[BYTES_IN_CLIENT_ID];
		uint8_t encryptedAesKey[BYTES_IN_ENCRYPTED_AES_KEY];

		Response_EncryptedAesPayload()
		{
			memset(clientID, 0, BYTES_IN_CLIENT_ID);
			memset(encryptedAesKey, 0, BYTES_IN_ENCRYPTED_AES_KEY);
		}
	};

	struct Response_CrcPayload
	{
		uint8_t clientID[BYTES_IN_CLIENT_ID];
		uint32_t contentSize;
		uint8_t fileName[BYTES_IN_FILE_NAME];
		uint32_t checksum;

		Response_CrcPayload() : contentSize(0), checksum(0)
		{
			memset(clientID, 0, BYTES_IN_CLIENT_ID);
			memset(fileName, 0, BYTES_IN_FILE_NAME);
		}
	};
#pragma pack(pop)
}