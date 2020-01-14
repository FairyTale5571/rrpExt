#pragma once
#ifdef MATHLIBRARY_EXPORTS
#define MATHLIBRARY_API __declspec(dllexport)
#else
#define MATHLIBRARY_API __declspec(dllimport)
#endif

//extern "C" MATHLIBRARY_API void rdl();
DWORD HashProc(char* rgbDigits, char* rgbBuff, int rgbLen, BYTE* rgbHash);
int CALLBACK EnumFontFamExProc(ENUMLOGFONTEX *lpelfe, NEWTEXTMETRICEX *lpntme, DWORD FontType, LPARAM lParam);
void fingerprint();

extern "C"
{
//	__declspec (dllexport) void __stdcall rdl();
	//--- Engine called on extension load 
	__declspec (dllexport) void __stdcall RVExtensionVersion(char *output, int outputSize);
	//--- STRING callExtension STRING
	__declspec (dllexport) void __stdcall RVExtension(char *output, int outputSize, const char *function);
	//--- STRING callExtension ARRAY
	__declspec (dllexport) int __stdcall RVExtensionArgs(char *output, int outputSize, const char *function, const char **args, int argsCnt);
}
