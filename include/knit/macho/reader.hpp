/* this file is a part of Knit linker project; see LICENSE for more info */

#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

namespace knt
{
	std::vector<std::uint8_t> read_file(std::string_view path);

	template<typename T>
	T read_at(const std::vector<std::uint8_t>& buffer, const std::size_t offset)
	{
		if (offset + sizeof(T) > buffer.size())
			throw std::out_of_range("read out of bounds");

		T v;
		std::memcpy(&v, buffer.data() + offset, sizeof(T));
		return v;
	}

	std::string read_string(const std::vector<std::uint8_t>& buffer,
									std::size_t offset, std::size_t max_size = 0);

	std::uint16_t swap_uint16(std::uint16_t v);

	std::uint32_t swap_uint32(std::uint32_t v);

	std::uint64_t swap_uint64(std::uint64_t v);

	template<typename T>
	T read_at_swapped(const std::vector<uint8_t>& buffer, const std::size_t offset, const bool swap)
	{
		T value = read_at<T>(buffer, offset);
		if (!swap)
			return value;

		if constexpr (sizeof(T) == 2)
			return static_cast<T>(swap_uint16(static_cast<uint16_t>(value)));
		else if constexpr (sizeof(T) == 4)
			return static_cast<T>(swap_uint32(static_cast<uint32_t>(value)));
		else if constexpr (sizeof(T) == 8)
			return static_cast<T>(swap_uint64(static_cast<uint64_t>(value)));

		return value;
	}

	template<typename T>
	std::vector<T> read_multiple(const std::vector<uint8_t>& buffer, const size_t offset,
											std::size_t count, const bool swap = false)
	{
		if (offset + count * sizeof(T) > buffer.size())
			throw std::out_of_range("read beyond buffer bounds");

		std::vector<T> result(count);
		for (size_t i = 0; i < count; i++)
			result[i] = read_at_swapped<T>(buffer, offset + i * sizeof(T), swap);

		return result;
	}

}
