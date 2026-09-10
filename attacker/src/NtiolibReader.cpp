#include "NtiolibReader.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace NtiolibReader {
    constexpr wchar_t driverPath[] = L"\\\\.\\NTIOLib_CC_Clock";
    constexpr DWORD ioctlHandshake = 0xC350214C;
    constexpr DWORD ioctlReadPhysical = 0xC3506104;
    constexpr DWORD handshakeValue = 0x2F405A34;
    constexpr std::uint8_t memoryResourceType = 3;
    constexpr std::uint8_t largeMemoryResourceType = 7;
    constexpr std::uint16_t largeMemory40Flag = 0x0200;
    constexpr std::uint16_t largeMemory48Flag = 0x0400;
    constexpr std::uint16_t largeMemory64Flag = 0x0800;
    constexpr std::uint64_t minimumReadablePhysicalAddress = UINT64_C(0x100000000);
    constexpr std::uint32_t maximumReadSize = 4 * 1024 * 1024;

#pragma pack(push, 4)
    struct TRawPartialResourceDescriptor {
        std::uint8_t type;
        std::uint8_t shareDisposition;
        std::uint16_t flags;
        std::uint8_t data[16];
    };
#pragma pack(pop)

    static_assert(sizeof(TRawPartialResourceDescriptor) == 20);
}

NtiolibReader::CPhysicalMemory::~CPhysicalMemory() {
    if (device != INVALID_HANDLE_VALUE) {
        CloseHandle(device);
    }
}

bool NtiolibReader::CPhysicalMemory::openDriver() {
    device = CreateFileW(
        driverPath,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD bytesReturned = 0;
    DWORD requestValue = handshakeValue;
    if (!DeviceIoControl(
            device,
            ioctlHandshake,
            &requestValue,
            sizeof(requestValue),
            nullptr,
            0,
            &bytesReturned,
            nullptr)) {
        CloseHandle(device);
        device = INVALID_HANDLE_VALUE;

        return false;
    }

    return true;
}

bool NtiolibReader::CPhysicalMemory::readPhysicalChunk(
    std::uint64_t address,
    void *output,
    std::uint32_t size) const {
    TReadRequest request = {address, 1, size};
    DWORD bytesReturned = 0;

    return DeviceIoControl(
               device,
               ioctlReadPhysical,
               &request,
               sizeof(request),
               output,
               size,
               &bytesReturned,
               nullptr) != FALSE &&
           bytesReturned == size;
}

bool NtiolibReader::CPhysicalMemory::loadWindowsRamRanges() {
    HKEY key = nullptr;
    constexpr wchar_t subkey[] =
        L"HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_QUERY_VALUE, &key) !=
        ERROR_SUCCESS) {
        return false;
    }

    DWORD type = 0;
    DWORD size = 0;
    LONG status =
        RegQueryValueExW(key, L".Translated", nullptr, &type, nullptr, &size);
    if (status != ERROR_SUCCESS || type != REG_RESOURCE_LIST || size < 20) {
        RegCloseKey(key);

        return false;
    }

    std::vector<std::uint8_t> buffer(size);
    status = RegQueryValueExW(
        key,
        L".Translated",
        nullptr,
        &type,
        buffer.data(),
        &size);
    RegCloseKey(key);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    const std::uint8_t *cursor = buffer.data();
    const std::uint8_t *end = buffer.data() + size;
    std::uint32_t fullCount = 0;
    std::memcpy(&fullCount, cursor, sizeof(fullCount));
    cursor += sizeof(fullCount);

    for (std::uint32_t fullIndex = 0; fullIndex < fullCount; ++fullIndex) {
        if (cursor + 16 > end) {
            return false;
        }

        std::uint32_t partialCount = 0;
        std::memcpy(&partialCount, cursor + 12, sizeof(partialCount));
        cursor += 16;

        for (std::uint32_t partialIndex = 0;
             partialIndex < partialCount;
             ++partialIndex) {
            if (cursor + sizeof(TRawPartialResourceDescriptor) > end) {
                return false;
            }

            const auto *descriptor =
                reinterpret_cast<const TRawPartialResourceDescriptor *>(cursor);
            if (descriptor->type == memoryResourceType ||
                descriptor->type == largeMemoryResourceType) {
                std::uint64_t start = 0;
                std::uint32_t encodedLength = 0;
                std::memcpy(&start, descriptor->data, sizeof(start));
                std::memcpy(
                    &encodedLength,
                    descriptor->data + 8,
                    sizeof(encodedLength));
                std::uint64_t length = encodedLength;
                if (descriptor->type == largeMemoryResourceType) {
                    if (descriptor->flags & largeMemory40Flag) {
                        length <<= 8;
                    } else if (descriptor->flags & largeMemory48Flag) {
                        length <<= 16;
                    } else if (descriptor->flags & largeMemory64Flag) {
                        length <<= 32;
                    } else {
                        return false;
                    }
                }

                const std::uint64_t rangeEnd = start + length;
                if (rangeEnd > start &&
                    rangeEnd > minimumReadablePhysicalAddress) {
                    const std::uint64_t readableStart =
                        std::max(start, minimumReadablePhysicalAddress);
                    ramRanges.push_back(
                        {readableStart, rangeEnd - readableStart});
                }
            }

            cursor += sizeof(TRawPartialResourceDescriptor);
        }
    }

    return !ramRanges.empty();
}

bool NtiolibReader::CPhysicalMemory::readPhysical(
    std::uint64_t address,
    void *output,
    std::size_t size) const {
    auto *destination = static_cast<std::uint8_t *>(output);
    std::size_t remaining = size;
    while (remaining != 0) {
        const TRamRange *containingRange = nullptr;
        for (const TRamRange &range : ramRanges) {
            if (address >= range.base && address < range.base + range.size) {
                containingRange = &range;
                break;
            }
        }

        if (containingRange == nullptr) {
            return false;
        }

        const std::uint64_t offset = address - containingRange->base;
        const std::size_t available =
            static_cast<std::size_t>(containingRange->size - offset);
        const std::uint32_t copySize = static_cast<std::uint32_t>(
            std::min<std::size_t>({remaining, available, maximumReadSize}));
        if (!readPhysicalChunk(address, destination, copySize)) {
            return false;
        }

        destination += copySize;
        address += copySize;
        remaining -= copySize;
    }

    return true;
}

bool NtiolibReader::CPhysicalMemory::findPhysicalPattern(
    const void *pattern,
    std::size_t patternSize,
    std::uint64_t minimumAddress,
    std::uint64_t &physicalAddress) const {
    if (pattern == nullptr || patternSize == 0) {
        return false;
    }

    const auto *patternBegin = static_cast<const std::uint8_t *>(pattern);
    std::vector<std::uint8_t> buffer(maximumReadSize + patternSize - 1);
    for (const TRamRange &range : ramRanges) {
        const std::uint64_t rangeEnd = range.base + range.size;
        std::uint64_t offset = minimumAddress > range.base
                                   ? minimumAddress - range.base
                                   : 0;
        if (range.base + offset >= rangeEnd) {
            continue;
        }

        std::size_t overlap = 0;
        while (range.base + offset < rangeEnd) {
            std::uint32_t readSize = static_cast<std::uint32_t>(
                std::min<std::uint64_t>(
                    maximumReadSize,
                    rangeEnd - (range.base + offset)));
            bool readSucceeded = false;
            while (readSize >= 4096) {
                if (readPhysicalChunk(
                        range.base + offset,
                        buffer.data() + overlap,
                        readSize)) {
                    readSucceeded = true;
                    break;
                }

                readSize /= 2;
            }

            if (!readSucceeded) {
                overlap = 0;
                offset += 4096;
                continue;
            }

            const std::uint8_t *begin = buffer.data();
            const std::uint8_t *end = begin + overlap + readSize;
            const std::uint8_t *match =
                std::search(begin, end, patternBegin, patternBegin + patternSize);
            if (match != end) {
                physicalAddress = range.base + offset - overlap +
                                  static_cast<std::uint64_t>(match - begin);

                return true;
            }

            overlap =
                std::min(patternSize - 1, static_cast<std::size_t>(readSize));
            std::memmove(buffer.data(), end - overlap, overlap);
            offset += readSize;
        }
    }

    return false;
}

std::size_t NtiolibReader::CPhysicalMemory::accessibleRangeCount() const {
    return ramRanges.size();
}

std::uint64_t NtiolibReader::CPhysicalMemory::accessibleByteCount() const {
    std::uint64_t total = 0;
    for (const TRamRange &range : ramRanges) {
        total += range.size;
    }

    return total;
}

std::uint64_t NtiolibReader::CPhysicalMemory::maximumPhysicalAddress() const {
    std::uint64_t maximumAddress = 0;
    for (const TRamRange &range : ramRanges) {
        maximumAddress =
            std::max(maximumAddress, range.base + range.size);
    }

    return maximumAddress;
}
