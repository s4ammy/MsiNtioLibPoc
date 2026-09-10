#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

constexpr std::size_t pageSize = 4096;
constexpr std::size_t requestedPageCount = 1048576;
constexpr char targetMagic[16] = {
    'M', 'S', 'I', '_', 'N', 'T', 'I', 'O', '_', 'V', 'I', 'C', 'T', 'I', 'M', '\0'
};

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

void FillPage(
    std::uint8_t *page,
    std::uint64_t seed,
    std::uint32_t processId,
    std::uint32_t pageIndex) {
    auto *header = reinterpret_cast<TSentinelHeader *>(page);
    std::memcpy(header->magic, targetMagic, sizeof(targetMagic));
    header->seed = seed;
    header->processId = processId;
    header->pageIndex = pageIndex;

    std::uint64_t state = InitialPageState(seed, processId, pageIndex);
    for (std::uint8_t &value : header->verifier) {
        value = static_cast<std::uint8_t>(NextRandom(state));
    }

    std::snprintf(
        header->text,
        sizeof(header->text),
        "Target-only memory read through MSI NTIOLib: pid=%lu page=%lu",
        static_cast<unsigned long>(processId),
        static_cast<unsigned long>(pageIndex));
}

bool EnableLockMemoryPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &token)) {
        return false;
    }

    LUID luid = {};
    if (!LookupPrivilegeValueW(nullptr, L"SeLockMemoryPrivilege", &luid)) {
        CloseHandle(token);

        return false;
    }

    TOKEN_PRIVILEGES privileges = {};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const BOOL adjusted = AdjustTokenPrivileges(
        token,
        FALSE,
        &privileges,
        sizeof(privileges),
        nullptr,
        nullptr);
    const DWORD error = GetLastError();
    CloseHandle(token);

    return adjusted != FALSE && error == ERROR_SUCCESS;
}

int main() {
    if (!EnableLockMemoryPrivilege()) {
        return 1;
    }

    ULONG_PTR pageCount = requestedPageCount;
    std::vector<ULONG_PTR> pageFrames(pageCount);
    if (!AllocateUserPhysicalPages(
            GetCurrentProcess(),
            &pageCount,
            pageFrames.data()) ||
        pageCount == 0) {
        return 1;
    }

    pageFrames.resize(pageCount);
    const std::size_t allocationSize = pageCount * pageSize;
    auto *pages = static_cast<std::uint8_t *>(VirtualAlloc(
        nullptr,
        allocationSize,
        MEM_RESERVE | MEM_PHYSICAL,
        PAGE_READWRITE));
    if (pages == nullptr) {
        FreeUserPhysicalPages(
            GetCurrentProcess(),
            &pageCount,
            pageFrames.data());

        return 1;
    }

    if (!MapUserPhysicalPages(pages, pageCount, pageFrames.data())) {
        VirtualFree(pages, 0, MEM_RELEASE);
        FreeUserPhysicalPages(
            GetCurrentProcess(),
            &pageCount,
            pageFrames.data());

        return 1;
    }

    const DWORD processId = GetCurrentProcessId();
    const std::uint64_t seed = DeriveSeed(processId);
    for (ULONG_PTR index = 0; index < pageCount; ++index) {
        FillPage(
            pages + index * pageSize,
            seed,
            processId,
            static_cast<std::uint32_t>(index));
    }

    Sleep(300000);
    MapUserPhysicalPages(pages, pageCount, nullptr);
    VirtualFree(pages, 0, MEM_RELEASE);
    FreeUserPhysicalPages(
        GetCurrentProcess(),
        &pageCount,
        pageFrames.data());

    return 0;
}
