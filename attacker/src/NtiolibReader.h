#pragma once

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace NtiolibReader {
    class CPhysicalMemory {
    public:
        CPhysicalMemory() = default;
        ~CPhysicalMemory();
        CPhysicalMemory(const CPhysicalMemory &other) = delete;
        CPhysicalMemory &operator=(const CPhysicalMemory &other) = delete;

        bool openDriver();
        bool loadWindowsRamRanges();
        bool readPhysical(std::uint64_t address, void *output, std::size_t size) const;
        bool findPhysicalPattern(
            const void *pattern,
            std::size_t patternSize,
            std::uint64_t minimumAddress,
            std::uint64_t &physicalAddress) const;

        std::size_t accessibleRangeCount() const;
        std::uint64_t accessibleByteCount() const;
        std::uint64_t maximumPhysicalAddress() const;

    private:
        struct TReadRequest {
            std::uint64_t physicalAddress;
            std::uint32_t unitSize;
            std::uint32_t unitCount;
        };

        struct TRamRange {
            std::uint64_t base;
            std::uint64_t size;
        };

        bool readPhysicalChunk(
            std::uint64_t address,
            void *output,
            std::uint32_t size) const;

        HANDLE device = INVALID_HANDLE_VALUE;
        std::vector<TRamRange> ramRanges;
    };
}
