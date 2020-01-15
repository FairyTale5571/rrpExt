// MathLibrary.cpp : Defines the exported functions for the DLL.
#include "pch.h" // use stdafx.h in Visual Studio 2017 and earlier
#include <utility>
#include <limits.h>
#include "MathLibrary.h"

#define _WIN32_DCOM
#include <iostream>
#include <fstream>
#include <comdef.h>
#include <Wbemidl.h>
#include <vector>
#include <string>
#include <sysinfoapi.h>
#include <windows.h>
#include <stdio.h>
#include<thread>
#include <wincrypt.h>
#include <iterator>
#include <sstream>
#include <cstring>


#pragma comment(lib, "wbemuuid.lib")
using namespace std;
#define CURRENT_VERSION "1.0.0 by FT5571 / rimasrp.life copyright"
#define BUFSIZE 1024
#define MD5LEN  16

//BSTR m_sireal;
char m_sireal[512];
char m_Hdsireal[20][512];
char m_HdCapacity[20][512];
char m_HdModel[20][512];
int m_DiskCount;
int m_DiskNo;
bool m_coreFlag = false;
int m_coreNum;
char m_rgbHashStr[33] = "";
char m_fingerBuff[10000] = "";
WCHAR m_old[250] = L"";

enum class WmiQueryError {
	None,
	BadQueryFailure,
	PropertyExtractionFailure,
	ComInitializationFailure,
	SecurityInitializationFailure,
	IWbemLocatorFailure,
	IWbemServiceConnectionFailure,
	BlanketProxySetFailure,
};

struct WmiQueryResult
{
	std::vector<std::wstring> ResultList;
	WmiQueryError Error = WmiQueryError::None;
	std::wstring ErrorDescription;
};

WmiQueryResult getWmiQueryResult(std::wstring wmiQuery, std::wstring propNameOfResultObject, bool allowEmptyItems = false) {

	WmiQueryResult retVal;
	retVal.Error = WmiQueryError::None;
	retVal.ErrorDescription = L"";

	HRESULT hres;
	IWbemLocator *pLoc = NULL;
	IWbemServices *pSvc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	IWbemClassObject *pclsObj = NULL;
	VARIANT vtProp;


	// Step 1: --------------------------------------------------
	// Initialize COM. ------------------------------------------

	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
		retVal.Error = WmiQueryError::ComInitializationFailure;
		retVal.ErrorDescription = L"Failed to initialize COM library. Error code : " + std::to_wstring(hres);
		strcpy_s(m_sireal, " **** Error1  ****");
	}
	else
	{
		// Step 2: --------------------------------------------------
		// Set general COM security levels --------------------------

		hres = CoInitializeSecurity(
			NULL,
			-1,                          // COM authentication
			NULL,                        // Authentication services
			NULL,                        // Reserved
			RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
			RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
			NULL,                        // Authentication info
			EOAC_NONE,                   // Additional capabilities 
			NULL                         // Reserved
		);


		if (FAILED(hres) && hres != RPC_E_TOO_LATE)
		{
			retVal.Error = WmiQueryError::SecurityInitializationFailure;
			retVal.ErrorDescription = L"Failed to initialize security. Error code : " + std::to_wstring(hres);
			_itoa_s(hres, m_sireal, 10);
			strcat_s(m_sireal, " **** Error2  ****");
//			strcpy_s(m_sireal, std::to_wstring(hres));
		}
		else
		{
			// Step 3: ---------------------------------------------------
			// Obtain the initial locator to WMI -------------------------
			pLoc = NULL;
			hres = CoCreateInstance(
				CLSID_WbemLocator,
				0,
				CLSCTX_INPROC_SERVER,
				IID_IWbemLocator, (LPVOID *)&pLoc);

			if (FAILED(hres))
			{
				retVal.Error = WmiQueryError::IWbemLocatorFailure;
				retVal.ErrorDescription = L"Failed to create IWbemLocator object. Error code : " + std::to_wstring(hres);
				strcpy_s(m_sireal, " **** Error3  ****");
			}
			else
			{
				// Step 4: -----------------------------------------------------
				// Connect to WMI through the IWbemLocator::ConnectServer method

				pSvc = NULL;

				// Connect to the root\cimv2 namespace with
				// the current user and obtain pointer pSvc
				// to make IWbemServices calls.
				hres = pLoc->ConnectServer(
					_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
					NULL,                    // User name. NULL = current user
					NULL,                    // User password. NULL = current
					0,                       // Locale. NULL indicates current
					NULL,                    // Security flags.
					0,                       // Authority (for example, Kerberos)
					0,                       // Context object 
					&pSvc                    // pointer to IWbemServices proxy
				);

				// Connected to ROOT\\CIMV2 WMI namespace

				if (FAILED(hres))
				{
					retVal.Error = WmiQueryError::IWbemServiceConnectionFailure;
					retVal.ErrorDescription = L"Could not connect to Wbem service.. Error code : " + std::to_wstring(hres);
					strcpy_s(m_sireal, " **** Error4  ****");
				}
				else
				{
					// Step 5: --------------------------------------------------
					// Set security levels on the proxy -------------------------

					hres = CoSetProxyBlanket(
						pSvc,                        // Indicates the proxy to set
						RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
						RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
						NULL,                        // Server principal name 
						RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
						RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
						NULL,                        // client identity
						EOAC_NONE                    // proxy capabilities 
					);

					if (FAILED(hres))
					{
						retVal.Error = WmiQueryError::BlanketProxySetFailure;
						retVal.ErrorDescription = L"Could not set proxy blanket. Error code : " + std::to_wstring(hres);
						strcpy_s(m_sireal, " **** Error5  ****");
					}
					else
					{
						// Step 6: --------------------------------------------------
						// Use the IWbemServices pointer to make requests of WMI ----

						// For example, get the name of the operating system
						pEnumerator = NULL;
						hres = pSvc->ExecQuery(
							bstr_t("WQL"),
							bstr_t(wmiQuery.c_str()),
							WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
							NULL,
							&pEnumerator);

						if (FAILED(hres))
						{
							retVal.Error = WmiQueryError::BadQueryFailure;
							retVal.ErrorDescription = L"Bad query. Error code : " + std::to_wstring(hres);
							strcpy_s(m_sireal, " **** Error6  ****");
						}
						else
						{
							// Step 7: -------------------------------------------------
							// Get the data from the query in step 6 -------------------

							pclsObj = NULL;
							ULONG uReturn = 0;

							while (pEnumerator)
							{
								HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
									&pclsObj, &uReturn);

								if (0 == uReturn)
								{
									break;
									strcpy_s(m_sireal, " **** Error7  ****");
								}

								// VARIANT vtProp;

								// Get the value of desired property
								hr = pclsObj->Get(propNameOfResultObject.c_str(), 0, &vtProp, 0, 0);
								if (S_OK != hr) {
									retVal.Error = WmiQueryError::PropertyExtractionFailure;
									retVal.ErrorDescription = L"Couldn't extract property: " + propNameOfResultObject + L" from result of query. Error code : " + std::to_wstring(hr);
									strcpy_s(m_sireal, " **** Error8  ****");
								}
								else {
									BSTR val = vtProp.bstrVal;

									// Sometimes val might be NULL even when result is S_OK
									// Convert NULL to empty string (otherwise "std::wstring(val)" would throw exception)
									if (NULL == val) {
										if (allowEmptyItems) {
//											retVal.ResultList.push_back(std::wstring(L""));
											strcpy_s(m_sireal, " **** Error9  ****");
										}
									}
									else {
//										retVal.ResultList.push_back(std::wstring(val));
										if (m_coreFlag) {
											m_coreNum = vtProp.intVal;
										}
										else {
											int i;
											switch (m_DiskNo)
											{
											case 1:
												for (i = 0;; i++) {
													if (vtProp.bstrVal[i] == '\0')
														break;
													m_HdModel[m_DiskCount][i] = (char)vtProp.bstrVal[i];
												}
												m_HdModel[m_DiskCount][i] = '\0';
												break;
											case 2:
												for (i = 0;; i++) {
													if (vtProp.bstrVal[i] == '\0')
														break;
													m_HdCapacity[m_DiskCount][i] = (char)vtProp.bstrVal[i];
												}
												m_HdCapacity[m_DiskCount][i] = '\0';
												break;
											case 3:
												for (i = 0;; i++) {
													if (vtProp.bstrVal[i] == '\0')
														break;
													m_Hdsireal[m_DiskCount][i] = (char)vtProp.bstrVal[i];
												}
												m_Hdsireal[m_DiskCount][i] = '\0';
												break;
											default:
												for (i = 0;; i++) {
													if (vtProp.bstrVal[i] == '\0')
														break;
													m_sireal[i] = (char)vtProp.bstrVal[i];
												}
												m_sireal[i] = '\0';
												break;
											}
											m_DiskCount++;
										}

									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Cleanup
	// ========

	VariantClear(&vtProp);
	if (pclsObj)
		pclsObj->Release();

	if (pSvc)
		pSvc->Release();

	if (pLoc)
		pLoc->Release();

	if (pEnumerator)
		pEnumerator->Release();

	CoUninitialize();

	return retVal;
}

void queryAndPrintResult(std::wstring query, std::wstring propNameOfResultObject)
{
	WmiQueryResult res;
	res = getWmiQueryResult(query, propNameOfResultObject);

	if (res.Error != WmiQueryError::None) {
		std::wcout << "Got this error while executing query: " << std::endl;
		std::wcout << res.ErrorDescription << std::endl;
//		strcpy_s(m_sireal, " **** Error10  ****");
		return; // Exitting function
	}

	for (const auto& item : res.ResultList) {
		std::wcout << item << std::endl;
		/*
		ofstream myfile;
		myfile.open("example.txt");
		myfile << item ;
		myfile.close();
		*/

	}
}

void strcopyN(char* string1, char* string2, int n) {
	for (int i = 0; i < n; i++) {
		string1[i] = string2[i];
	}
}

//--- Extension version information shown in .rpt file
void __stdcall RVExtensionVersion(char *output, int outputSize)
{
	//--- max outputSize is 32 bytes
	strncpy_s(output, outputSize, CURRENT_VERSION, _TRUNCATE);
}

//--- name callExtension function
void __stdcall RVExtension(char *output, int outputSize, const char *function)
{
	std::string str = function;
	strncpy_s(output, outputSize, ("Input Was: " + str).c_str(), _TRUNCATE);
}

//--- name callExtension [function, args]
int __stdcall RVExtensionArgs(char *output, int outputSize, const char *function, const char **args, int argsCnt)
{
	if (strcmp(function, "getHardwares") == 0)
	{
		//--- Manually assemble output array
		int i = 0;
//		std::string str[7] = { "HDD","CPU","GPU","MOTHERBOARD",	"BIOS",	"RAM","FINGER" };
		std::string str[8];

		while (i < argsCnt)
		{
			std::string s= args[i];
			str[i] = s.substr(1, s.length() - 2);
			i++;
		}

		int j;
		i = 0;
		for (j = 0; j < outputSize; j++) {
			output[j] = NULL;
		}
		for (int a = 0; a < argsCnt; a++, output[i++] = ',') {
//		for (int a = 0; a < 7; a++, output[i++] = ',') {
			m_DiskCount = 0;
			m_DiskNo = 0;
			if (str[a].compare("HDDQ")==0) {
				m_DiskCount = 0;
				m_DiskNo = 1;
				//Get Hdd serial
				queryAndPrintResult(L"SELECT * FROM Win32_DiskDrive ", L"Model");
				m_DiskCount = 0;
				m_DiskNo = 2;
				//Get Hdd Capacity
				queryAndPrintResult(L"SELECT * FROM Win32_DiskDrive ", L"Size");
				m_DiskCount = 0;
				m_DiskNo = 3;
				//Get Hdd serial
				queryAndPrintResult(L"SELECT SerialNumber FROM Win32_PhysicalMedia", L"SerialNumber");
//				i = 1;
				for (int k = m_DiskCount - 1; k >= 0; k--, output[i++] = ',') {
					output[i++] = '[';
					output[i++] = '"';
					for (j = 0;; i++, j++) {
						if (m_HdModel[k][j] == '\0')
							break;
						output[i] = m_HdModel[k][j];
					}
					output[i++] = ' ';
					if (k == m_DiskCount - 1) {
						char test[20] = { "" };
						for (j = 0;; j++) {
							if (m_HdCapacity[k][j] == '\0')
								break;
							test[j] = m_HdCapacity[k][j];
						}
						double hdSize = (double)atoll(test);
						float hsize = (float)(hdSize / 1024000000000l);
						strcpy_s(test, "");
						snprintf(test, sizeof 3, "%f", hsize);
						strcat_s(test, "TB ");
						for (j = 0;; i++, j++) {
							if (test[j] == '\0')
								break;
							output[i] = test[j];
						}
					}

					for (j = 0;; i++, j++) {
						if (m_Hdsireal[k][j] == '\0')
							break;
						output[i] = m_Hdsireal[k][j];
					}
					output[i++] = '"';
					output[i++] = ']';
				}
				output[i - 1] = '\0';
				i--;
				continue;
			}
			if (str[a].compare("CPUQ") == 0) {
				//Get model of cpu
				queryAndPrintResult(L"SELECT * From Win32_Processor", L"Name");
				output[i++] = '[';
				output[i++] = '"';
				for (j = 0;; i++, j++) {
					if (m_sireal[j] == '\0')
						break;
					output[i] = m_sireal[j];
				}
				output[i++] = '"';
				output[i++] = ',';
				// Get id of CPU----------------------------------------------------------------------------------------------
				queryAndPrintResult(L"SELECT ProcessorId FROM Win32_Processor", L"ProcessorId");
				output[i++] = '"';
				for (j = 0;; i++, j++) {
					if (m_sireal[j] == '\0')
						break;
					output[i] = m_sireal[j];
				}
				output[i++] = '"';
				output[i++] = ']';
				continue;
			}
			if (str[a].compare("GPUQ") == 0) {
				//Get GPU info
				queryAndPrintResult(L"SELECT * FROM Win32_VideoController ", L"Name");
				output[i++] = '[';
				output[i++] = '"';
				strcopyN(&output[i], (char*)("GPU "), 4);
				i += 4;
				for (j = 0;; i++, j++) {
					if (m_sireal[j] == '\0')
						break;
					output[i] = m_sireal[j];
				}
				output[i++] = '"';
				output[i++] = ']';
				continue;
			}
			if (str[a].compare("MOTHERBOARDQ") == 0) {
				//Get MotherbordName
				queryAndPrintResult(L"Select  *  from  Win32_BaseBoard ", L"Product");
				output[i++] = '[';
				output[i++] = '"';
				strcopyN(&output[i], (char*)("Motherboard "), 12);
				i += 12;
				for (j = 0;; i++, j++) {
					if (m_sireal[j] == '\0')
						break;
					output[i] = m_sireal[j];
				}
				output[i++] = '"';
				output[i++] = ']';
				continue;
			}
			if (str[a].compare("BIOSQ") == 0) {
				// Get Bios info(CompanyName)
				queryAndPrintResult(L"select * from Win32_BIOS ", L"Manufacturer");
				output[i++] = '[';
				output[i++] = '"';
				strcopyN(&output[i], (char*)("BIOS "), 5);
				//	strcpy_s(&output[i], 5, "BIOS, ");
				i += 5;
				for (j = 0;; i++, j++) {
					if (m_sireal[j] == '\0')
						break;
					output[i] = m_sireal[j];
				}
				output[i++] = '"';
				output[i++] = ']';
				continue;
			}
			if (str[a].compare("RAMQ") == 0) {
				//Get Ram info
				queryAndPrintResult(L"SELECT * FROM Win32_PhysicalMemory ", L"Manufacturer");
				output[i++] = '[';
				output[i++] = '"';
				strcopyN(&output[i], (char*)("RAM "), 4);
				i += 4;
				for (j = 0;; i++, j++) {
					if (m_sireal[j] == '\0')
						break;
					output[i] = m_sireal[j];
				}
				output[i++] = ' ';
				m_DiskCount = 0;
				m_DiskNo = 2;
				queryAndPrintResult(L"SELECT * FROM Win32_PhysicalMemory ", L"Capacity"); ///RAM
				float hsize = 0;
				for (int k = m_DiskCount - 1; k >= 0; k--) {
					char test[20] = { "" };
					for (j = 0;; j++) {
						if (m_HdCapacity[k][j] == '\0')
							break;
						test[j] = m_HdCapacity[k][j];
					}
					double hdSize = (double)atoll(test);
					hsize += (float)(hdSize / 1024000000l);
				}
				char test[20] = { "" };
				strcpy_s(test, "");
				snprintf(test, sizeof 3, "%f", hsize);
				strcat_s(test, "GB");
				for (j = 0;; i++, j++) {
					if (test[j] == '\0')
						break;
					output[i] = test[j];
				}
				output[i++] = '"';
				output[i++] = ']';
				continue;
			}
			if (str[a].compare("FINGERQ") == 0) {
				fingerprint();
				output[i++] = '[';
				output[i++] = '"';
				strcopyN(&output[i], (char*)(""), 7);
				i += 7;
				strcopyN(&output[i], m_rgbHashStr, 32);
				i += 32;
				output[i++] = '"';
				output[i++] = ']';
				continue;
			}
		}
		output[i-1] = '\0';
//		printf(output);
		return 100;
	}

	else if (strcmp(function, "getVersion") == 0)
	{
		//--- Parse args into vector
		std::vector<std::string> vec(args, std::next(args, argsCnt));

		std::ostringstream oss;
		if (!vec.empty())
		{
			//--- Assemble output array
			std::copy(vec.begin(), vec.end() - 1, std::ostream_iterator<std::string>(oss, ","));
			oss << vec.back();
		}

		//--- Extension result
		strncpy_s(output, outputSize, ("Version 1.0.1 by FT5571" + oss.str() + "").c_str(), _TRUNCATE);

		//--- Extension return code
		return 200;
	}

	else
	{
		strncpy_s(output, outputSize, "Avaliable Functions: getVersion, getHardwares", outputSize - 1);
		return -1;
	}
}
///   FontName Get callback fuction
int CALLBACK EnumFontFamExProc(ENUMLOGFONTEX *lpelfe,NEWTEXTMETRICEX *lpntme,DWORD FontType,LPARAM lParam)
{	
	if (wcscmp(m_old, lpelfe->elfFullName) == 0)
		return 1;
	wcscpy_s(m_old, lpelfe->elfFullName);
	int len = 0;
	len =(int)wcslen(lpelfe->elfFullName);
	char* ptr = (char*)lpelfe->elfFullName;
	for (int i = 0; i < len; i++) {
		strcat_s(m_fingerBuff, (char*)&lpelfe->elfFullName[i]);
	}
//	wprintf_s(m_old);
	//Return non--zero to continue enumeration
	return 1;
}
void fingerprint() {
	m_fingerBuff[0] = '\0';
	queryAndPrintResult(L"SELECT * FROM Win32_SystemTimeZone", L"Setting");        //////  TimeZone
	strcat_s(m_fingerBuff, m_sireal);
	queryAndPrintResult(L"SELECT * FROM Win32_OperatingSystem", L"Version");      ////////  System ver,build
	strcat_s(m_fingerBuff, m_sireal);
	m_coreFlag = true;
	queryAndPrintResult(L"SELECT * FROM Win32_Processor", L"NumberOfCores");   //// Core count
	char corNum[4] = "";
	_itoa_s(m_coreNum, corNum, 10);
	strcat_s(m_fingerBuff, corNum);
	m_coreFlag = false;
	queryAndPrintResult(L"SELECT * FROM Win32_NetworkAdapterConfiguration", L"MACAddress");   //// MacAddress
	strcat_s(m_fingerBuff, m_sireal);

	char width[6] = "";
	char heith[6] = "";
	int x = GetSystemMetrics(SM_CXSCREEN);    //////////////   Disply width
	int y = GetSystemMetrics(SM_CYSCREEN);    /////////////      Heidth
	_itoa_s(x, width, 10);
	_itoa_s(y, heith, 10);
	strcat_s(m_fingerBuff, width);
	strcat_s(m_fingerBuff, heith);
	//////  GetUserDefaultLocaleName//////
	WCHAR localeName[LOCALE_NAME_MAX_LENGTH] = { 0 };
	std::cout << "Calling GetUserDefaultLocaleName";
	int ret = GetUserDefaultLocaleName(localeName, 85);
	if (ret == 0)
		std::cout << "Cannot retrieve the default locale name." << std::endl;
	else
		std::wcout << localeName << std::endl;
	int len = (int)wcslen(localeName);
	for (int i = 0; i < len; i++) {
		strcat_s(m_fingerBuff, (char*)(&localeName[i]));
	}
	///////////////////////  Font Names          ///////////////////////////////
	LOGFONT lf;
	lf.lfFaceName[0] = '\0';
	lf.lfCharSet = DEFAULT_CHARSET;
	HDC hDC = ::GetDC(NULL);
	EnumFontFamiliesEx(hDC, &lf, (FONTENUMPROC)&EnumFontFamExProc, 0, 0);
	::ReleaseDC(NULL, hDC);
	//////////////////////////////////////////////////////////
//	printf(m_fingerBuff);
	CHAR rgbDigits[] = "0123456789abcdef";
	BYTE rgbHash[MD5LEN];
	len = (int)strlen(m_fingerBuff);
	HashProc(rgbDigits, m_fingerBuff, len, rgbHash);
	m_rgbHashStr[0] = '\0';
	for (int c = 0; c < MD5LEN; c++) {
		char buff[3] = "";
		_itoa_s(rgbHash[c], buff, 16);
		if(strlen(buff) == 1)
			strcat_s(m_rgbHashStr, "0");

		strcat_s(m_rgbHashStr, buff);
	}
}


DWORD HashProc(char* rgbDigits, char* rgbBuff, int rgbLen, BYTE* rgbHash)
{
	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	DWORD cbRead = 0;
	DWORD cbHash = 0;


	// Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		return dwStatus;
	}

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		return dwStatus;
	}

	if (!CryptHashData(hHash, (BYTE*)rgbBuff, rgbLen, 0))
	{
		dwStatus = GetLastError();
		printf("CryptHashData failed: %d\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return dwStatus;
	}

	cbHash = MD5LEN;
	if (CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)rgbHash, &cbHash, 0))
	{
//		printf("MD5 hash of file %s is: ", filename);
		for (DWORD i = 0; i < cbHash; i++)
		{
			printf("%c%c", rgbDigits[rgbHash[i] >> 4],
				rgbDigits[rgbHash[i] & 0xf]);
		}
		printf("\n");
	}
	else
	{
		dwStatus = GetLastError();
		printf("CryptGetHashParam failed: %d\n", dwStatus);
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);

	return dwStatus;
}