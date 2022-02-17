#pragma once

#pragma warning(disable: 4005)
#pragma warning(disable: 4055)
#pragma warning(disable: 4152)
#pragma warning(disable: 4201)
#pragma warning(disable: 6102)
#pragma warning(disable: 6258)
#pragma warning(disable: 6320)
#pragma warning(disable: 6255 6263)
#pragma warning(disable: 4996)

#include <Windows.h>
#include <ntstatus.h>
#include <CommCtrl.h>
#include <shlobj.h>
#include <AccCtrl.h>

#define T_CLSID_CMSTPLUA                     L"{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
#define T_ELEVATION_MONIKER_ADMIN            L"Elevation:Administrator!new:"

#define UCM_DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
     EXTERN_C const GUID DECLSPEC_SELECTANY name \
                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }  

UCM_DEFINE_GUID(IID_ICMLuaUtil, 0x6EDD6D74, 0xC007, 0x4E75, 0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C);

typedef interface ICMLuaUtil ICMLuaUtil;

typedef struct ICMLuaUtilVtbl {

	BEGIN_INTERFACE

		HRESULT(STDMETHODCALLTYPE* QueryInterface)(
			__RPC__in ICMLuaUtil* This,
			__RPC__in REFIID riid,
			_COM_Outptr_  void** ppvObject);

	ULONG(STDMETHODCALLTYPE* AddRef)(
		__RPC__in ICMLuaUtil* This);

	ULONG(STDMETHODCALLTYPE* Release)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* SetRasCredentials)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* SetRasEntryProperties)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* DeleteRasEntry)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* LaunchInfSection)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* LaunchInfSectionEx)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* CreateLayerDirectory)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* ShellExec)(
		__RPC__in ICMLuaUtil* This,
		_In_     LPCTSTR lpFile,
		_In_opt_  LPCTSTR lpParameters,
		_In_opt_  LPCTSTR lpDirectory,
		_In_      ULONG fMask,
		_In_      ULONG nShow);

	END_INTERFACE

} *PICMLuaUtilVtbl;

interface ICMLuaUtil { CONST_VTBL struct ICMLuaUtilVtbl* lpVtbl; };
