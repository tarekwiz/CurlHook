// dllmain.cpp : Defines the entry point for the DLL application.

#include <iostream>
#include <windows.h>
#include <cstdint>
#include <Windows.h>
#include <vector>
#include <TlHelp32.h>
#include <Psapi.h>
#include "detours.h"
#include <intrin.h>

#pragma intrinsic(_ReturnAddress)

#pragma comment(lib, "detours.lib")
#define DEBUG 0

namespace Iat_hook
{
	void** find(const char* function, HMODULE module)
	{
		if (!module)
			module = GetModuleHandle(0);

		PIMAGE_DOS_HEADER img_dos_headers = (PIMAGE_DOS_HEADER)module;
		PIMAGE_NT_HEADERS img_nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)img_dos_headers + img_dos_headers->e_lfanew);
		PIMAGE_IMPORT_DESCRIPTOR img_import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)img_dos_headers + img_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		if (img_dos_headers->e_magic != IMAGE_DOS_SIGNATURE)
			printf("ERROR: e_magic is no valid DOS signature\n");

		for (IMAGE_IMPORT_DESCRIPTOR* iid = img_import_desc; iid->Name != 0; iid++) {
			for (int func_idx = 0; *(func_idx + (void**)(iid->FirstThunk + (size_t)module)) != nullptr; func_idx++) {
				char* mod_func_name = (char*)(*(func_idx + (size_t*)(iid->OriginalFirstThunk + (size_t)module)) + (size_t)module + 2);
				const intptr_t nmod_func_name = (intptr_t)mod_func_name;
				if (nmod_func_name >= 0) {
					if (!::strcmp(function, mod_func_name))
						return func_idx + (void**)(iid->FirstThunk + (size_t)module);
				}
			}
		}
		return 0;
	}

	uintptr_t detour_iat_ptr(const char* function, void* newfunction, HMODULE module = 0)
	{
		auto&& func_ptr = find(function, module);
		if (*func_ptr == newfunction || *func_ptr == nullptr)
			return 0;

		DWORD old_rights, new_rights = PAGE_READWRITE;
		VirtualProtect(func_ptr, sizeof(uintptr_t), new_rights, &old_rights);
		uintptr_t ret = (uintptr_t)* func_ptr;
		*func_ptr = newfunction;
		VirtualProtect(func_ptr, sizeof(uintptr_t), old_rights, &new_rights);
		return ret;
	}
};


#define CURLOPT_SSL_VERIFYPEER 64
#define CURLOPT_SSL_VERIFYHOST 81
#define CURLOPT_PROXY_SSL_VERIFYPEER 248
#define CURLOPT_PROXY_SSL_VERIFYHOST 249
#define CURLOPT_SSL_CTX_FUNCTION 20108
#define CURLOPT_SSL_CTX_DATA 10109
#define CURLOPT_CERTINFO 172

struct Curl_easy {
	/* first, two fields for the linked list of these */
	struct Curl_easy* next;
	struct Curl_easy* prev;
};

struct Curl_multi {
	/* First a simple identifier to easier detect if a user mix up
	   this multi handle with an easy handle. Set this to CURL_MULTI_HANDLE. */
	long type;

	/* We have a doubly-linked circular list with easy handles */
	struct Curl_easy* easyp; /* first node*/
	struct Curl_easy* easylp; /* last node */
};

typedef SOCKET curl_socket_t;
struct curl_waitfd {
	curl_socket_t fd;
	short events;
	short revents; /* not supported yet */
};


typedef int(__cdecl* tcurl_easy_setopt)(Curl_easy* handle, int option, ...);
tcurl_easy_setopt curl_easy_setopt;

typedef int(__cdecl* tcurl_multi_perform)(Curl_multi* multi_handle, int* running_handles);
tcurl_multi_perform curl_multi_perform_original;

typedef int(__cdecl* tcurl_easy_perform)(struct Curl_easy* data);
tcurl_easy_perform curl_easy_perform_original;

typedef int(__cdecl* tcurl_multi_socket_action)(struct Curl_multi* multi, curl_socket_t s,
	int ev_bitmask, int* running_handles);
tcurl_multi_socket_action curl_multi_socket_action_original;


void disableSSL(struct Curl_easy* data)
{
	//just disable SSL checks.
	curl_easy_setopt(data, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(data, CURLOPT_SSL_VERIFYHOST, 0L);
	curl_easy_setopt(data, CURLOPT_PROXY_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(data, CURLOPT_PROXY_SSL_VERIFYHOST, 0L);
	curl_easy_setopt(data, CURLOPT_SSL_CTX_FUNCTION, NULL);
	curl_easy_setopt(data, CURLOPT_SSL_CTX_DATA, NULL);
	curl_easy_setopt(data, CURLOPT_CERTINFO, 0L);
}

int curl_multi_socket_action_hook(struct Curl_multi* multi, curl_socket_t s, int ev_bitmask, int* running_handles)
{
  //std::cout << "curl_multi_socket_action_hook" << std::endl;
	//Iterate over each request
	auto iterator = multi->easyp;
	while (iterator != NULL)
	{
		disableSSL(iterator);
		iterator = iterator->next;
	}
	return curl_multi_socket_action_original(multi, s, ev_bitmask, running_handles);
}

int curl_easy_perform_hook(struct Curl_easy* data)
{
  //std::cout << "curl_easy_perform_hook" << std::endl;
	disableSSL(data);
	return curl_easy_perform_original(data);
}

int curl_multi_perform_hook(Curl_multi* multi_handle, int* running_handles)
{
  //std::cout << "curl_multi_perform_hook" << std::endl;
	
	//Iterate over each request
	auto iterator = multi_handle->easyp;
	while (iterator != NULL)
	{
		disableSSL(iterator);
		iterator = iterator->next;
	}

	return curl_multi_perform_original(multi_handle, running_handles);
}

MODULEINFO GetModuleInfo(char* szModule)
{
  MODULEINFO modInfo = { 0 };
  HMODULE hModule = GetModuleHandleA(szModule);
  if (hModule != 0)
    GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));
  return modInfo;
}

uintptr_t FindPattern(DWORD base, DWORD size, char* pattern, char* mask)
{
  auto patternLength = strlen(mask);

  for (int i = 0; i < size - patternLength; i++)
  {
    bool found = true;
    for (int j = 0; j < patternLength; j++)
    {
      found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);
    }
    if (found)
      return base + i;
  }
  return NULL;
}

uintptr_t GetProcedure(char* module, char* pattern, char* mask)
{
  MODULEINFO modInfo = { 0 };
  HMODULE hModule = GetModuleHandleA(module);
  if (!hModule)
    return 0;

  GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));
  MODULEINFO mInfo = GetModuleInfo(module);
  auto base = (DWORD)mInfo.lpBaseOfDll;
  auto size = mInfo.SizeOfImage;
  
  return FindPattern(base, size, pattern, mask);
}

uintptr_t GetPointer(char* module, char* pattern, char* mask, int32_t start)
{
  MODULEINFO modInfo = { 0 };
  HMODULE hModule = GetModuleHandleA(module);
  if (!hModule)
    return 0;

  GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));
  MODULEINFO mInfo = GetModuleInfo(module);
  auto base = (DWORD)mInfo.lpBaseOfDll;
  auto size = mInfo.SizeOfImage;


  uintptr_t signatureAddress = FindPattern(base, size, pattern, mask) + start;

  uintptr_t fileOffset = signatureAddress - base;

  uintptr_t offset = *reinterpret_cast<int32_t*>(signatureAddress);
  return base + (offset + fileOffset);
}



typedef void(__cdecl* tSSL_CTX_set_verify)(void* ctx, int mode, int (*callback)(void*, void*));
tSSL_CTX_set_verify SSL_CTX_set_verify_original;

void SSL_CTX_set_verify_hook(void* ctx, int mode, int (*callback)(void*, void*))
{
  mode = 0; //SSL_NOVERIFY
  return SSL_CTX_set_verify_original(ctx, mode, NULL);
}

typedef void(__cdecl* tSSL_set_verify)(void* ctx, int mode, int (*callback)(void*, void*));
tSSL_set_verify SSL_set_verify_original;

void SSL_set_verify_hook(void* ctx, int mode, int (*callback)(void*, void*))
{
  mode = 0; //SSL_NOVERIFY
  return SSL_set_verify_original(ctx, mode, NULL);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
#if DEBUG
      AllocConsole();
      freopen("CONOUT$", "w", stdout);
#endif
      //Find the function address of the function curl_easy_setopt
      curl_easy_setopt = (tcurl_easy_setopt)GetProcAddress(GetModuleHandleA("libcurl"), "curl_easy_setopt");

      //Curl is probably not exported or imported, so we pattern find it.
      if (!curl_easy_setopt)
      {

        //Find the functions using Pattern scanning.

        //NOTE NEED TO ADD curl_easy_perform
        curl_easy_setopt = (tcurl_easy_setopt)(GetProcedure(NULL, (char*)"\x55\x8B\xEC\x8B\x45\x08\x85\xC0\x75\x07\xB8\x2B\x00\x00\x00\x5D\xC3", (char*)"xxxxxxxxxxxxxxxxx"));
        curl_multi_perform_original = (tcurl_multi_perform)(GetPointer(NULL, (char*)"\xE8\x00\x00\x00\x00\x8B\xF0\x83\xC4\x08\x85\xF6\x75\x20", (char*)"x????xxxxxxxxx", 0x1) + 0x4);
        curl_multi_socket_action_original = *(tcurl_multi_socket_action)(GetProcedure(NULL, (char*)"\x55\x8B\xEC\x56\x8B\x75\x08\x80\xBE\x00\x00\x00\x00\x00\x74\x08\xB8\x00\x00\x00\x00\x5E\x5D\xC3\x57\xFF\x75\x14", (char*)"xxxxxxxxx?????xxx????xxxxxxx"));
        SSL_CTX_set_verify_original = (tSSL_CTX_set_verify)(GetProcedure(NULL, (char*)"\x8B\x4C\x24\x04\x8B\x44\x24\x08\x89\x81\xD0\x00\x00\x00\x8B\x44\x24\x0C\x89\x81\xF8\x00\x00\x00\xC3", (char*)"xxxxxxxxxxxxxxxxxxxxxxxxx"));
        SSL_set_verify_original = (tSSL_set_verify)(GetProcedure(NULL,         (char*)"\x8B\x4C\x24\x04\x8B\x44\x24\x08\x89\x81\xA8\x04\x00\x00\x8B\x44\x24\x0C\x85\xC0\x74\x06\x89\x81\xAC\x04\x00\x00\xC3", (char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        
        SSL_CTX_set_verify_original = (tSSL_CTX_set_verify)DetourFunction((PBYTE)(SSL_CTX_set_verify_original), (PBYTE)SSL_CTX_set_verify_hook);
        SSL_set_verify_original = (tSSL_set_verify)DetourFunction((PBYTE)(SSL_set_verify_original), (PBYTE)SSL_set_verify_hook);
        curl_multi_perform_original = (tcurl_multi_perform)DetourFunction((PBYTE)(curl_multi_perform_original), (PBYTE)curl_multi_perform_hook);
        curl_multi_socket_action_original = (tcurl_multi_socket_action)DetourFunction((PBYTE)(curl_multi_socket_action_original), (PBYTE)curl_multi_socket_action_hook);
      }
      else
      {
        //use IAT to hook perform functions
        curl_multi_perform_original = *(tcurl_multi_perform)Iat_hook::detour_iat_ptr("curl_multi_perform", (void*)curl_multi_perform_hook);
        curl_easy_perform_original = *(tcurl_easy_perform)Iat_hook::detour_iat_ptr("curl_easy_perform", (void*)curl_easy_perform_hook);
        curl_multi_socket_action_original = *(tcurl_multi_socket_action)Iat_hook::detour_iat_ptr("curl_multi_socket_action", (void*)curl_multi_socket_action_hook);
        SSL_CTX_set_verify_original = (tSSL_CTX_set_verify)DetourFunction((PBYTE)GetProcAddress(GetModuleHandleA("libssl-1_1"), "SSL_CTX_set_verify"), (PBYTE)SSL_CTX_set_verify_hook);
        SSL_set_verify_original = (tSSL_set_verify)DetourFunction((PBYTE)GetProcAddress(GetModuleHandleA("libssl-1_1"), "SSL_set_verify"), (PBYTE)SSL_set_verify_hook);
      }
    

		break;
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}