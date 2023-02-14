/*****************************************************************//**
 * \file   Utilities.h
 * \brief  A small collection of utilities for the project.
 * 
 * \author aaron
 * \date   February 2023
 *********************************************************************/
#pragma once
#include <sstream>
#include <string>
#include <vector>

namespace Utilities
{
	namespace Endianess
	{
		inline bool isLittleEndian()
		{
			const int num = 1;
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
	}

	namespace UUID
	{
		constexpr size_t UUID_SIZE = 16;
		const std::vector<uint8_t> convertUuidFromAsciiToRaw(const std::string& uuidASCII)
		{
			std::vector<uint8_t> buffer(UUID_SIZE);
			for (int i = 0; i < UUID_SIZE * 2; i += 2)
			{
				buffer[i / 2] = static_cast<uint8_t>(strtoul(uuidASCII.substr(i, 2).c_str(), nullptr, std::ios_base::hex));
			}
			return buffer;
		}


		const std::string convertUuidFromRawToAscii(const std::vector<uint8_t>& uuidRAW)
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
}