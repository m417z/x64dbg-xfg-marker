#include "pch.h"

#define PLUGIN_VERSION 101
#define PLUGIN_VERSION_STR "1.0.1"

#ifndef DLL_EXPORT
#define DLL_EXPORT __declspec(dllexport)
#endif

#ifndef IMAGE_GUARD_XFG_ENABLED
#define IMAGE_GUARD_XFG_ENABLED 0x00800000
#endif

#ifndef IMAGE_GUARD_FLAG_FID_XFG
#define IMAGE_GUARD_FLAG_FID_XFG 8  // Call target supports XFG
#endif

namespace {

enum {
    MENU_XFG_MARK = 1,
    MENU_ABOUT,
};

HINSTANCE g_hDllInst;
int g_pluginHandle;

class SymbolInfoWrapper {
   public:
    SymbolInfoWrapper() = default;
    ~SymbolInfoWrapper() { free(); }

    SymbolInfoWrapper(const SymbolInfoWrapper&) = delete;
    SymbolInfoWrapper& operator=(const SymbolInfoWrapper&) = delete;

    SYMBOLINFO* put() {
        free();
        memset(&info, 0, sizeof(info));
        return &info;
    }

    const SYMBOLINFO* get() const { return &info; }
    const SYMBOLINFO* operator->() const { return &info; }

   private:
    void free() {
        if (info.freeDecorated) {
            BridgeFree(info.decoratedSymbol);
        }
        if (info.freeUndecorated) {
            BridgeFree(info.undecoratedSymbol);
        }
    }

    SYMBOLINFO info{};
};

DWORD_PTR GetCpuModule() {
    SELECTIONDATA selection;
    if (!GuiSelectionGet(GUI_DISASSEMBLY, &selection)) {
        return 0;
    }

    return DbgFunctions()->ModBaseFromAddr(selection.start);
}

DWORD_PTR GetNtHeader(DWORD_PTR module) {
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)module;

    LONG ntHeaderOffset;
    if (!DbgMemRead((DWORD_PTR)&dosHeader->e_lfanew, &ntHeaderOffset,
                    sizeof(ntHeaderOffset))) {
        return 0;
    }

    return module + ntHeaderOffset;
}

DWORD GetPeDirectory(IMAGE_NT_HEADERS* ntHeaders,
                     DWORD directory,
                     DWORD* sizeOut) {
    DWORD numberOfRvaAndSizes;
    if (!DbgMemRead((DWORD_PTR)&ntHeaders->OptionalHeader.NumberOfRvaAndSizes,
                    &numberOfRvaAndSizes, sizeof(numberOfRvaAndSizes))) {
        return 0;
    }

    if (numberOfRvaAndSizes <= directory) {
        return 0;
    }

    DWORD virtualAddress;
    if (!DbgMemRead(
            (DWORD_PTR)&ntHeaders->OptionalHeader.DataDirectory[directory]
                .VirtualAddress,
            &virtualAddress, sizeof(virtualAddress))) {
        return 0;
    }

    DWORD size;
    if (!DbgMemRead(
            (DWORD_PTR)&ntHeaders->OptionalHeader.DataDirectory[directory].Size,
            &size, sizeof(size))) {
        return 0;
    }

    *sizeOut = size;
    return virtualAddress;
}

template <typename T>
bool ReadMemAndAdvance(DWORD_PTR* address, T* target) {
    if (!DbgMemRead(*address, target, sizeof(*target))) {
        return false;
    }

    *address += sizeof(*target);
    return true;
}

DWORD_PTR GetCfgFunctionTable(DWORD_PTR module,
                              DWORD_PTR* guardCFFunctionCountOut,
                              DWORD* guardFlagsOut) {
    DWORD_PTR ntHeader = GetNtHeader(module);
    if (!ntHeader) {
        return 0;
    }

    DWORD loadConfigSize;
    DWORD loadConfig =
        GetPeDirectory((IMAGE_NT_HEADERS*)ntHeader,
                       IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &loadConfigSize);
    if (!loadConfig || loadConfigSize < sizeof(DWORD)) {
        return 0;
    }

    DWORD_PTR cfgFieldsPtr = module + loadConfig;

    DWORD loadConfigDataSize;
    if (!DbgMemRead(cfgFieldsPtr, &loadConfigDataSize,
                    sizeof(loadConfigDataSize))) {
        return 0;
    }

    // Magic offset reference:
    // https://github.com/Vector35/view-pe/blob/3c5cfcf19a46a063c506cd5799e173a6c5482b8a/peview.cpp#L1881
#ifdef _WIN64
    const DWORD_PTR cfgFieldsOffset = 112;
#else
    const DWORD_PTR cfgFieldsOffset = 72;
#endif
    const DWORD_PTR cfgFieldsDesiredSize =
        sizeof(DWORD_PTR) * 4 + sizeof(DWORD);

    if (loadConfigDataSize < cfgFieldsOffset + cfgFieldsDesiredSize) {
        return 0;
    }

    cfgFieldsPtr += cfgFieldsOffset;

    DWORD_PTR guardCFCheckFunctionPointer;
    if (!ReadMemAndAdvance(&cfgFieldsPtr, &guardCFCheckFunctionPointer)) {
        return 0;
    }

    DWORD_PTR guardCFDispatchFunctionPointer;
    if (!ReadMemAndAdvance(&cfgFieldsPtr, &guardCFDispatchFunctionPointer)) {
        return 0;
    }

    DWORD_PTR guardCFFunctionTable;
    if (!ReadMemAndAdvance(&cfgFieldsPtr, &guardCFFunctionTable)) {
        return 0;
    }

    DWORD_PTR guardCFFunctionCount;
    if (!ReadMemAndAdvance(&cfgFieldsPtr, &guardCFFunctionCount)) {
        return 0;
    }

    DWORD guardFlags;
    if (!ReadMemAndAdvance(&cfgFieldsPtr, &guardFlags)) {
        return 0;
    }

    *guardCFFunctionCountOut = guardCFFunctionCount;
    *guardFlagsOut = guardFlags;

    return guardCFFunctionTable;
}

#ifdef _WIN64
using ExecutableRegionsMap =
    std::map<DWORD_PTR, std::vector<BYTE>, std::greater<DWORD_PTR>>;

ExecutableRegionsMap GetModuleExecutableRegionsMap(DWORD_PTR module,
                                                   DWORD_PTR* warningCount) {
    constexpr DWORD_PTR kPageSize = 0x1000;

    DWORD_PTR moduleSize = DbgFunctions()->ModSizeFromAddr(module);
    DWORD_PTR moduleEnd = module + moduleSize;

    ExecutableRegionsMap executableRegions;

    for (DWORD_PTR p = module; p < moduleEnd; p += kPageSize) {
        DWORD_PTR executableRegionAddress = p;
        DWORD_PTR executableRegionSize = 0;

        for (; p < moduleEnd; p += kPageSize) {
            char rights[RIGHTS_STRING_SIZE];
            if (!DbgFunctions()->GetPageRights(p, rights)) {
                (*warningCount)++;
                _plugin_logprintf(
                    "Warning: Failed to get page access rights for %p\n", p);
                break;
            }

            if (rights[0] != 'E') {
                break;
            }

            executableRegionSize += kPageSize;
        }

        if (!executableRegionSize) {
            continue;
        }

        std::vector<BYTE> buffer(executableRegionSize, 0);
        if (!DbgMemRead(executableRegionAddress, buffer.data(),
                        buffer.size())) {
            (*warningCount)++;
            _plugin_logprintf("Warning: Failed to read %p bytes at %p\n",
                              buffer.size(), executableRegionAddress);
            continue;
        }

        executableRegions[executableRegionAddress] = std::move(buffer);
    }

    return executableRegions;
}

std::string GetCommentForXfgTargets(std::span<const DWORD_PTR> xfgEntries) {
    std::string comment = std::to_string(xfgEntries.size()) + "fn: ";

    bool first = true;

    for (DWORD_PTR xfgEntry : xfgEntries) {
        if (first) {
            first = false;
        } else {
            comment += ", ";
        }

        DWORD_PTR function = xfgEntry + sizeof(DWORD_PTR);

        SymbolInfoWrapper info;
        char symbolNameOnly[1024];
        if (!DbgGetSymbolInfoAt(function, info.put()) ||
            !info->decoratedSymbol ||
            !UnDecorateSymbolName(info->decoratedSymbol, symbolNameOnly,
                                  ARRAYSIZE(symbolNameOnly),
                                  UNDNAME_NAME_ONLY)) {
            char buffer[32];
            sprintf_s(buffer, "%p", reinterpret_cast<void*>(function));
            comment += buffer;
        } else {
            comment += symbolNameOnly;
        }
    }

    return comment;
}

struct MarkXrefAndCommentsResult {
    DWORD_PTR xrefCount;
    DWORD_PTR commentCount;
    DWORD_PTR warningCount;
};

std::optional<MarkXrefAndCommentsResult> MarkXrefAndComments(
    DWORD_PTR module,
    std::span<const DWORD_PTR> xfgEntries) {
    MarkXrefAndCommentsResult result{};

    auto executableRegions =
        GetModuleExecutableRegionsMap(module, &result.warningCount);

    struct XfgHashInfo {
        std::vector<DWORD_PTR> entries;
        std::string comment;
    };

    std::unordered_map<DWORD_PTR, XfgHashInfo> xfgHashes;

    for (DWORD_PTR xfgEntry : xfgEntries) {
        // Find the executable region starting at or before the xfg entry.
        auto it = executableRegions.lower_bound(xfgEntry);
        if (it == executableRegions.end()) {
            result.warningCount++;
            _plugin_logprintf(
                "Warning: Failed to find memory region for XFG entry %p\n",
                xfgEntry);
            continue;
        }

        DWORD_PTR executableRegionAddress = it->first;
        DWORD_PTR executableRegionSize = it->second.size();

        DWORD_PTR xfgEntryOffset = xfgEntry - executableRegionAddress;
        if (xfgEntryOffset + sizeof(DWORD_PTR) >
            executableRegionAddress + executableRegionSize) {
            result.warningCount++;
            _plugin_logprintf(
                "Warning: Failed to find memory region for XFG entry %p\n",
                xfgEntry);
            continue;
        }

        DWORD_PTR xfgHash =
            *reinterpret_cast<DWORD_PTR*>(it->second.data() + xfgEntryOffset) &
            ~1;
        xfgHashes[xfgHash].entries.push_back(xfgEntry);
    }

    // For example: 49:BA 70D95B74A18F04A6 | mov r10,A6048FA1745BD970
    constexpr BYTE kXfgHashUsagePrefix[] = {0x49, 0xBA};

    for (const auto& [executableRegionAddress, executableRegion] :
         executableRegions) {
        auto p = executableRegion.begin();

        while (true) {
            auto it = std::search(p, executableRegion.end(),
                                  std::begin(kXfgHashUsagePrefix),
                                  std::end(kXfgHashUsagePrefix));
            if (it == executableRegion.end()) {
                break;
            }

            p = it + ARRAYSIZE(kXfgHashUsagePrefix);
            if (p + sizeof(DWORD_PTR) > executableRegion.end()) {
                break;
            }

            DWORD_PTR xfgHash = *reinterpret_cast<const DWORD_PTR*>(&*p) & ~1;
            auto xfgHashInfoIt = xfgHashes.find(xfgHash);
            if (xfgHashInfoIt == xfgHashes.end()) {
                continue;
            }

            auto& xfgHashInfo = xfgHashInfoIt->second;

            DWORD_PTR xfgUsageCommand =
                executableRegionAddress + (it - executableRegion.begin());

            for (DWORD_PTR xfgEntry : xfgHashInfo.entries) {
                DWORD_PTR function = xfgEntry + sizeof(DWORD_PTR);
                DbgXrefAdd(xfgUsageCommand, function);
                DbgXrefAdd(function, xfgUsageCommand);
                result.xrefCount++;
            }

            if (xfgHashInfo.comment.empty()) {
                xfgHashInfo.comment =
                    GetCommentForXfgTargets(xfgHashInfo.entries);
            }

            DbgSetAutoCommentAt(xfgUsageCommand, xfgHashInfo.comment.c_str());
            result.commentCount++;
        }
    }

    return result;
}
#endif  // _WIN64

bool XfgMark() {
    DWORD_PTR module = GetCpuModule();
    if (!module) {
        _plugin_logputs("No module in the CPU view");
        return false;
    }

    DWORD_PTR cfgFunctionCount;
    DWORD guardFlags;
    DWORD_PTR cfgFunctionTable =
        GetCfgFunctionTable(module, &cfgFunctionCount, &guardFlags);
    if (!cfgFunctionTable) {
        _plugin_logputs("No CFG function table found");
        return false;
    }

    if ((guardFlags & IMAGE_GUARD_XFG_ENABLED) == 0) {
        _plugin_logputs("XFG isn't enabled for the target module");
        return false;
    }

    DWORD mdSize = (guardFlags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >>
                   IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT;
    if (mdSize == 0) {
        _plugin_logputs("mdSize is zero");
        return false;
    }

    // Reference:
    // https://github.com/Vector35/view-pe/blob/3c5cfcf19a46a063c506cd5799e173a6c5482b8a/peview.cpp#L1943-L1958

    DWORD_PTR cfgFunctionTablePtr = cfgFunctionTable;

    std::vector<DWORD_PTR> xfgEntries;

    DWORD_PTR xfgEntriesMarked = 0;
    DWORD_PTR warningCount = 0;

    for (DWORD_PTR i = 0; i < cfgFunctionCount; i++) {
        DWORD rva;
        if (!ReadMemAndAdvance(&cfgFunctionTablePtr, &rva)) {
            _plugin_logprintf("DbgMemRead failed at %p\n", cfgFunctionTablePtr);
            return false;
        }

        BYTE value;
        if (!DbgMemRead(cfgFunctionTablePtr, &value, sizeof(value))) {
            _plugin_logprintf("DbgMemRead failed at %p\n", cfgFunctionTablePtr);
            return false;
        }

        if ((value & IMAGE_GUARD_FLAG_FID_XFG) != 0) {
            DWORD_PTR xfgEntry = module + rva - 8;
            xfgEntries.push_back(xfgEntry);

            if (DbgSetEncodeType(xfgEntry, 8, enc_qword)) {
                xfgEntriesMarked++;
            } else {
                warningCount++;
                _plugin_logprintf("Warning: Failed to mark %p XFG entry\n",
                                  xfgEntry);
            }
        }

        cfgFunctionTablePtr += mdSize;
    }

    if (!xfgEntries.empty()) {
        // GuiUpdateDisassemblyView didn't always work for me. Reference for
        // DbgCmdExec:
        // https://github.com/x64dbg/x64dbg/blob/b6348f5b791899125003be156b2323d0c763f161/src/dbg/commands/cmd-types.cpp#L31
        DbgCmdExec("disasm dis.sel()");

        std::string msg;

        if (xfgEntries.size() == xfgEntriesMarked) {
            msg += "Found and marked " + std::to_string(xfgEntries.size()) +
                   " XFG entries";
        } else {
            msg += "Found " + std::to_string(xfgEntries.size()) +
                   " XFG entries, marked " + std::to_string(xfgEntriesMarked) +
                   " entries";
        }

#ifdef _WIN64
        if (auto markXrefAndCommentsResult =
                MarkXrefAndComments(module, xfgEntries)) {
            if (markXrefAndCommentsResult->xrefCount > 0) {
                msg += ", added " +
                       std::to_string(markXrefAndCommentsResult->xrefCount) +
                       " xrefs";
            }

            if (markXrefAndCommentsResult->commentCount > 0) {
                msg += ", added " +
                       std::to_string(markXrefAndCommentsResult->commentCount) +
                       " comments";
            }

            warningCount += markXrefAndCommentsResult->warningCount;
        }
#endif  // _WIN64

        if (warningCount > 0) {
            msg += " (" + std::to_string(warningCount) + " warnings, see log)";
        }

        _plugin_logputs(msg.c_str());
    } else {
        _plugin_logputs("No XFG entries were found");
    }

    return true;
}

bool XfgMarkCmd(int argc, char** argv) {
    if (argc > 1) {
        _plugin_logputs("Command does not accept arguments");
        return false;
    }

    return XfgMark();
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            g_hDllInst = hModule;
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }

    return TRUE;
}

extern "C" DLL_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct) {
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strcpy_s(initStruct->pluginName, "XFG Marker");
    g_pluginHandle = initStruct->pluginHandle;

    _plugin_logputs("XFG Marker v" PLUGIN_VERSION_STR);
    _plugin_logputs("  By m417z");

    _plugin_registercommand(g_pluginHandle, "xfg_mark", XfgMarkCmd, true);

    return true;
}

extern "C" DLL_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct) {
    int hMenu = setupStruct->hMenu;

    _plugin_menuaddentry(hMenu, MENU_XFG_MARK, "Mark &XFG");
    _plugin_menuaddseparator(hMenu);
    _plugin_menuaddentry(hMenu, MENU_ABOUT, "&About");

    _plugin_menuentrysethotkey(g_pluginHandle, MENU_XFG_MARK, "Ctrl+Shift+X");
}

extern "C" DLL_EXPORT void CBMENUENTRY(CBTYPE, PLUG_CB_MENUENTRY* info) {
    switch (info->hEntry) {
        case MENU_XFG_MARK:
            if (!DbgIsDebugging()) {
                break;
            }

            XfgMark();
            break;

        case MENU_ABOUT:
            MessageBox(
                GetActiveWindow(),
                L"XFG Marker v" TEXT(PLUGIN_VERSION_STR) L"\n" 
                L"By m417z\n" 
                L"https://github.com/m417z/x64dbg-xfg-marker",
                L"About", MB_ICONINFORMATION);
            break;
    }
}
