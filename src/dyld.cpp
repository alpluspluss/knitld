/* this file is a part of Knit linker project; see LICENSE for more info */

#include <exception>
#include <knit/dyld.hpp>
#include <knit/mach-o.hpp>

namespace knt
{
	std::uint64_t read_uleb128(const std::uint8_t *data, std::size_t &offset)
	{
		if (!data)
			throw std::runtime_error("read_uleb128: null data pointer");

		std::uint64_t result = 0;
		std::uint64_t shift = 0;
		std::uint8_t byte;
		do
		{
			byte = data[offset++];
			result |= (static_cast<std::uint64_t>(byte & 0x7F) << shift);
			shift += 7;
		}
		while (byte & 0x80);

		return result;
	}

	std::uint64_t read_sleb128(const std::uint8_t *data, std::size_t &offset)
	{
		if (!data)
			throw std::runtime_error("read_uleb128: null data pointer");

		std::uint64_t result = 0;
		std::uint64_t shift = 0;
		std::uint8_t byte;
		do
		{
			byte = data[offset++];
			result |= (static_cast<std::uint64_t>(byte & 0x7F) << shift);
			shift += 7;
		}
		while (byte & 0x80);

		/* sign extend */
		if (shift < 64 && (byte & 0x40))
			result |= static_cast<std::uint64_t>(-1) << shift;

		return static_cast<std::int64_t>(result);
	}

	std::uint64_t compute_addr(const std::vector<SegmentInfo> &segs, const std::uint8_t segment_index,
	                           const std::uint64_t segment_offset)
	{
		return segment_index < segs.size() ? segs[segment_index].vmaddr + segment_offset : 0;
	}
}
