/*****************************************************************//**
 * \file   Utilities.h
 * \brief  A small collection of utilities for the project.
 * 
 * \author aaron
 * \date   February 2023
 *********************************************************************/
#pragma once
#include "CRC.h"

#include <fstream>
#include <sstream>
#include <random>
#include <string>
#include <vector>

namespace Utilities
{
	namespace Endianess
	{
		static inline bool isLittleEndian()
		{
			const int num = 1;
			return (*(char*)&num == 1) ? true : false;
		}


		template <typename intType>
		static void changeEndianness(intType& src)
		{
			uint8_t buffer[sizeof(intType)] = { 0 };
			memcpy(buffer, &src, sizeof(intType));
			std::reverse(buffer, buffer + sizeof(intType));
			memcpy(&src, buffer, sizeof(intType));
		}
	}

	namespace UUID
	{
		static constexpr size_t UUID_SIZE = 16;
		static const std::vector<uint8_t> convertUuidFromAsciiToRaw(const std::string& uuidASCII)
		{
			std::vector<uint8_t> buffer(UUID_SIZE);
			for (int i = 0; i < UUID_SIZE * 2; i += 2)
			{
				buffer[i / 2] = static_cast<uint8_t>(strtoul(uuidASCII.substr(i, 2).c_str(), nullptr, 16));
			}
			return buffer;
		}


		static const std::string convertUuidFromRawToAscii(const std::vector<uint8_t>& uuidRAW)
		{
			std::stringstream ss;
			for (int i = 0; i < UUID_SIZE; ++i)
			{
				uint8_t val = static_cast<uint8_t>(uuidRAW[i]);
				if (16 > val)
				{
					ss << "0";
				}
				ss << std::hex << static_cast<int>(val);
			}
			return ss.str();
		}
	}

	namespace CRC32
	{
		static uint32_t calculateFileCRC(const std::string& filePath)
		{
			std::ifstream file;
			file.exceptions(std::ios::badbit);
			file.open(filePath);
			constexpr size_t BUFFER_SIZE = 1024;
			char buffer[BUFFER_SIZE + 1] = { 0 };
			file.read(buffer, BUFFER_SIZE);
			uint32_t crc = crc = CRC::Calculate(buffer, strlen(buffer), CRC::CRC_32());
			while (!file.eof())
			{
				memset(buffer, 0, BUFFER_SIZE + 1);
				file.read(buffer, BUFFER_SIZE);
				crc = CRC::Calculate(buffer, strlen(buffer), CRC::CRC_32(), crc);
			}
			file.close();
			return crc;
		}
	}

	namespace Random
	{
		static std::string randomString(const size_t length)
		{
			auto randchar = []() -> char
			{
				const char charset[] =
					"0123456789"
					"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
					"abcdefghijklmnopqrstuvwxyz";
				const size_t max_index = (sizeof(charset) - 1);
				return charset[rand() % max_index];
			};
			std::string str(length, 0);
			std::generate_n(str.begin(), length, randchar);
			return str;
		}
	}
}