/*
 * These are SSPI authentication routines for the NTLM module of CNTLM
 * Used only on Win32/64 (Cygwin)
 *
 * CNTLM is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * CNTLM is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
 * St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Copyright (c) 2013 Denis Galkin aka Evengard, David Kubicek
 *
 */

#ifdef __CYGWIN__

#include "sspi.h"

// SSPI mode
#ifdef UNICODE
wchar_t* sspi_mode = NULL;
#else
char* sspi_mode = NULL;
#endif

// Security DLL handle
HMODULE sspi_dll = NULL;

// Function pointers
ACCEPT_SECURITY_CONTEXT_FN       _AcceptSecurityContext     = NULL;
ACQUIRE_CREDENTIALS_HANDLE_FN    _AcquireCredentialsHandle  = NULL;
COMPLETE_AUTH_TOKEN_FN           _CompleteAuthToken         = NULL;
DELETE_SECURITY_CONTEXT_FN       _DeleteSecurityContext     = NULL;
FREE_CONTEXT_BUFFER_FN           _FreeContextBuffer         = NULL;
FREE_CREDENTIALS_HANDLE_FN       _FreeCredentialsHandle     = NULL;
INITIALIZE_SECURITY_CONTEXT_FN   _InitializeSecurityContext = NULL;
QUERY_SECURITY_PACKAGE_INFO_FN   _QuerySecurityPackageInfo  = NULL;
QUERY_SECURITY_CONTEXT_TOKEN_FN  _QuerySecurityContextToken = NULL;

void UnloadSecurityDll(HMODULE hModule) {

	if (hModule)
		FreeLibrary(hModule);

	_AcceptSecurityContext      = NULL;
	_AcquireCredentialsHandle   = NULL;
	_CompleteAuthToken          = NULL;
	_DeleteSecurityContext      = NULL;
	_FreeContextBuffer          = NULL;
	_FreeCredentialsHandle      = NULL;
	_InitializeSecurityContext  = NULL;
	_QuerySecurityPackageInfo   = NULL;
	_QuerySecurityContextToken  = NULL;
}

HMODULE LoadSecurityDll(void) {

	HMODULE hModule;
	BOOL    fAllFunctionsLoaded = FALSE;
	TCHAR   lpszDLL[MAX_PATH];
	OSVERSIONINFO VerInfo;

	//
	//  Find out which security DLL to use, depending on
	//  whether we are on Windows NT or Windows 95, Windows 2000, Windows XP, or Windows Server 2003
	//  We have to use security.dll on Windows NT 4.0.
	//  All other operating systems, we have to use Secur32.dll
	//
	VerInfo.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
	if (!GetVersionEx (&VerInfo))   // If this fails, something has gone wrong
	{
		return FALSE;
	}

	if (VerInfo.dwPlatformId == VER_PLATFORM_WIN32_NT &&
		VerInfo.dwMajorVersion == 4 &&
		VerInfo.dwMinorVersion == 0)
	{
		lstrcpy (lpszDLL, TEXT("security.dll"));
	}
	else
	{
		lstrcpy (lpszDLL, TEXT("secur32.dll"));
	}


	hModule = LoadLibrary(lpszDLL);
	if (!hModule)
		return NULL;

	do {
		_AcceptSecurityContext = (ACCEPT_SECURITY_CONTEXT_FN)
				GetProcAddress(hModule, "AcceptSecurityContext");
		if (!_AcceptSecurityContext)
			break;

#ifdef UNICODE
		_AcquireCredentialsHandle = (ACQUIRE_CREDENTIALS_HANDLE_FN)
				GetProcAddress(hModule, "AcquireCredentialsHandleW");
#else
		_AcquireCredentialsHandle = (ACQUIRE_CREDENTIALS_HANDLE_FN)
				GetProcAddress(hModule, "AcquireCredentialsHandleA");
#endif
		if (!_AcquireCredentialsHandle)
			break;

		// CompleteAuthToken is not present on Windows 9x Secur32.dll
		// Do not check for the availability of the function if it is NULL;
		_CompleteAuthToken = (COMPLETE_AUTH_TOKEN_FN)
				GetProcAddress(hModule, "CompleteAuthToken");

		_DeleteSecurityContext = (DELETE_SECURITY_CONTEXT_FN)
				GetProcAddress(hModule, "DeleteSecurityContext");
		if (!_DeleteSecurityContext)
			break;

		_FreeContextBuffer = (FREE_CONTEXT_BUFFER_FN)
				GetProcAddress(hModule, "FreeContextBuffer");
		if (!_FreeContextBuffer)
			break;

		_FreeCredentialsHandle = (FREE_CREDENTIALS_HANDLE_FN)
				GetProcAddress(hModule, "FreeCredentialsHandle");
		if (!_FreeCredentialsHandle)
			break;

#ifdef UNICODE
		_InitializeSecurityContext = (INITIALIZE_SECURITY_CONTEXT_FN)
				GetProcAddress(hModule, "InitializeSecurityContextW");
#else
		_InitializeSecurityContext = (INITIALIZE_SECURITY_CONTEXT_FN)
				GetProcAddress(hModule, "InitializeSecurityContextA");
#endif
		if (!_InitializeSecurityContext)
			break;

#ifdef UNICODE
		_QuerySecurityPackageInfo = (QUERY_SECURITY_PACKAGE_INFO_FN)
				GetProcAddress(hModule, "QuerySecurityPackageInfoW");
#else
		_QuerySecurityPackageInfo = (QUERY_SECURITY_PACKAGE_INFO_FN)
				GetProcAddress(hModule, "QuerySecurityPackageInfoA");
#endif
		if (!_QuerySecurityPackageInfo)
			break;

		_QuerySecurityContextToken = (QUERY_SECURITY_CONTEXT_TOKEN_FN)
				GetProcAddress(hModule, "QuerySecurityContextToken");
		if (!_QuerySecurityContextToken)
			break;

		fAllFunctionsLoaded = TRUE;

	} while (NULL);

	if (!fAllFunctionsLoaded) {
		UnloadSecurityDll(hModule);
		hModule = NULL;
	}

	return hModule;
}

int sspi_enabled(void)
{
	if (sspi_mode != NULL)
		return 1;
	return 0;
}

int sspi_set(char* mode)
{
	sspi_dll = LoadSecurityDll();
	if (!strcasecmp("NTLM", mode) && sspi_dll)  // Only NTLM supported for now
	{
#ifdef UNICODE
		sspi_mode = zmalloc(sizeof(wchar_t) * strlen(mode));
		mbstowcs(sspi_mode, mode, strlen(mode));
#else
		sspi_mode = strdup(mode);
#endif
		return 1;
	}
	sspi_mode = NULL;
	return 0;
}

int sspi_unset(void)
{
	free(sspi_mode);
	sspi_mode = NULL;
	UnloadSecurityDll(sspi_dll);
	sspi_dll = NULL;
	return 1;
}

int sspi_request(char **dst, struct sspi_handle *sspi)
{
	SECURITY_STATUS status;
	TimeStamp expiry;

	status = _AcquireCredentialsHandle(
		NULL, // Use current principal
		sspi_mode,
		SECPKG_CRED_OUTBOUND,
		NULL,
		NULL,
		NULL,
		NULL,
		&sspi->credentials,
		&expiry);

	if (status != SEC_E_OK)
		return 0;

	SecBufferDesc   tokenDesc;
	SecBuffer       token;
	unsigned long attrs;

	tokenDesc.ulVersion = SECBUFFER_VERSION;
	tokenDesc.cBuffers  = 1;
	tokenDesc.pBuffers  = &token;
	token.cbBuffer   = TOKEN_BUFSIZE;
	token.BufferType = SECBUFFER_TOKEN;
	token.pvBuffer   = zmalloc(TOKEN_BUFSIZE);

	status = _InitializeSecurityContext(
		&sspi->credentials,
		NULL,
		TEXT(""),
		ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONNECTION,
		0,
		SECURITY_NETWORK_DREP,
		NULL,
		0,
		&sspi->context,
		&tokenDesc,
		&attrs,
		&expiry);

	if(status == SEC_I_COMPLETE_AND_CONTINUE || status == SEC_I_CONTINUE_NEEDED)
		_CompleteAuthToken(&sspi->context, &tokenDesc);
	else if(status != SEC_E_OK)
	{
		_FreeCredentialsHandle(&sspi->context);
		return 0;
	}

	*dst = token.pvBuffer;
	return token.cbBuffer;
}

int sspi_response(char **dst, char *challengeBuf, int challen, struct sspi_handle *sspi)
{
	SecBuffer challenge;
	SecBuffer answer;
	SecBufferDesc challengeDesc;
	SecBufferDesc answerDesc;
	SECURITY_STATUS status;
	unsigned long attrs;
	TimeStamp expiry;

	challengeDesc.ulVersion = answerDesc.ulVersion  = SECBUFFER_VERSION;
	challengeDesc.cBuffers  = answerDesc.cBuffers   = 1;

	challengeDesc.pBuffers  = &challenge;
	answerDesc.pBuffers  = &answer;

	challenge.BufferType = answer.BufferType = SECBUFFER_TOKEN;

	challenge.pvBuffer   = challengeBuf;
	challenge.cbBuffer   = challen;
	answer.pvBuffer   = zmalloc(TOKEN_BUFSIZE);
	answer.cbBuffer   = TOKEN_BUFSIZE;

	status = _InitializeSecurityContext(
		&sspi->credentials,
		&sspi->context,
		TEXT(""),
		ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONNECTION,
		0,
		SECURITY_NETWORK_DREP,
		&challengeDesc,
		0,
		&sspi->context,
		&answerDesc,
		&attrs,
		&expiry);

	if(status != SEC_E_OK)
		return 0;

	*dst = answer.pvBuffer;
	return answer.cbBuffer;
}

#endif /*  __CYGWIN__ */
