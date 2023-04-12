#include "pch.h"

#define PLUGIN_VERSION 10
#define PLUGIN_VERSION_STR "1.0"

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
};

HINSTANCE g_hDllInst;

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

    DWORD_PTR xfgCount = 0;
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
            if (!DbgSetEncodeType(xfgEntry, 8, enc_qword)) {
                _plugin_logprintf("Warning: Failed to mark %p XFG entry\n",
                                  xfgEntry);
            } else {
                xfgCount++;
            }
        }

        cfgFunctionTablePtr += mdSize;
    }

    if (xfgCount > 0) {
        // GuiUpdateDisassemblyView didn't always work for me. Reference for
        // DbgCmdExec:
        // https://github.com/x64dbg/x64dbg/blob/b6348f5b791899125003be156b2323d0c763f161/src/dbg/commands/cmd-types.cpp#L31
        DbgCmdExec("disasm dis.sel()");

        _plugin_logprintf("Marked %" PRIuPTR " XFG entries\n", xfgCount);
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

#ifdef __cplusplus
extern "C" {
#endif

DLL_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct);
DLL_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct);
DLL_EXPORT CDECL void CBWINEVENT(CBTYPE cbType, PLUG_CB_WINEVENT* info);
DLL_EXPORT CDECL void CBMENUENTRY(CBTYPE cbType, void* callbackInfo);

#ifdef __cplusplus
}
#endif

DLL_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct) {
    int hMenu = setupStruct->hMenu;

    _plugin_menuaddentry(hMenu, MENU_XFG_MARK, "Mark &XFG\tCtrl+Shift+X");
}

DLL_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct) {
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strcpy_s(initStruct->pluginName, "XFG Marker");
    int pluginHandle = initStruct->pluginHandle;

    _plugin_logputs("XFG Marker v" PLUGIN_VERSION_STR);
    _plugin_logputs("  By m417z");

    _plugin_registercommand(pluginHandle, "xfg_mark", XfgMarkCmd, true);

    return true;
}

DLL_EXPORT CDECL void CBWINEVENT(CBTYPE cbType, PLUG_CB_WINEVENT* info) {
    MSG* pMsg = info->message;

    if (info->result && pMsg->message == WM_KEYUP && pMsg->wParam == 'X') {
        bool ctrlDown = GetKeyState(VK_CONTROL) < 0;
        bool altDown = GetKeyState(VK_MENU) < 0;
        bool shiftDown = GetKeyState(VK_SHIFT) < 0;

        if (!altDown && ctrlDown && shiftDown) {
            XfgMark();
            *info->result = 0;
            info->retval = true;
            return;
        }
    }
}

DLL_EXPORT CDECL void CBMENUENTRY(CBTYPE cbType, void* callbackInfo) {
    XfgMark();
}
