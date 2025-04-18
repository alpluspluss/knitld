/* this file is a part of Knit linker project; see LICENSE for more info */

#include <fcntl.h>
#include <fstream>
#include <unistd.h>
#include <knit/reader.hpp>
#include <sys/mman.h>
#include <sys/stat.h>

namespace knt
{
    std::vector<std::uint8_t> read_file(const std::string_view path)
    {
        /* open the file */
        const int fd = open(path.data(), O_RDONLY);
        if (fd == -1)
            throw std::runtime_error("failed to open file: " + std::string(path));

        /* get file size */
        struct stat sb = {};
        if (fstat(fd, &sb) == -1)
        {
            close(fd);
            throw std::runtime_error("failed to stat file: " + std::string(path));
        }

        const size_t size = sb.st_size;
        void* mapped_data = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (mapped_data == MAP_FAILED)
        {
            close(fd);
            throw std::runtime_error("failed to mmap file: " + std::string(path));
        }

        std::vector<std::uint8_t> buffer;
        buffer.resize(size);
        std::memcpy(buffer.data(), mapped_data, size);

        /* clean up */
        munmap(mapped_data, size);
        close(fd);
        return buffer;
    }

    std::string read_string(const std::vector<std::uint8_t>& buffer, const std::size_t offset, const std::size_t max_size)
    {
        if (offset >= buffer.size())
            throw std::out_of_range("read beyond buffer bounds");

        std::size_t len = 0;
        if (max_size > 0)
        {
            /* read const-string until NULL */
            while (len < max_size && offset + len < buffer.size() && buffer[offset + len] != 0)
                len++;
        }
        else /* null-terminated */
        {
            while (offset + len < buffer.size() && buffer[offset + len] != 0)
                len++;
        }

        return { reinterpret_cast<const char*>(buffer.data() + offset), len };
    }

    std::uint16_t swap_uint16(std::uint16_t v)
    {
        return ((v & 0xFF) << 8) | ((v & 0xFF00) >> 8);
    }

    std::uint32_t swap_uint32(std::uint32_t v)
    {
        return ((v & 0xFF) << 24) |
               ((v & 0xFF00) << 8) |
               ((v & 0xFF0000) >> 8) |
               ((v & 0xFF000000) >> 24);
    }

    std::uint64_t swap_uint64(std::uint64_t v)
    {
        return ((v & 0xFF) << 56) |
               ((v & 0xFF00) << 40) |
               ((v & 0xFF0000) << 24) |
               ((v & 0xFF000000) << 8) |
               ((v & 0xFF00000000) >> 8) |
               ((v & 0xFF0000000000) >> 24) |
               ((v & 0xFF000000000000) >> 40) |
               ((v & 0xFF00000000000000) >> 56);
    }
}
