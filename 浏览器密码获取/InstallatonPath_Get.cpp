#include "pch.h"
#include"Firefox_decrypt.h"
#define MY_BUFSIZE 128 // Arbitrary initial value.
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383
#define Key32READ  KEY_READ
#define Key64READ  KEY_READ | KEY_WOW64_64KEY
// Dynamic allocation will be used.
constexpr auto Get_failed = "get_InstallationPath Failed";

BOOL IsWow64()
{
	typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;
	BOOL bIsWow64 = FALSE;
	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(("kernel32")), "IsWow64Process");
	if (NULL != fnIsWow64Process)
	{
		fnIsWow64Process(GetCurrentProcess(), &bIsWow64);
	}
	return bIsWow64;
}

// 通过注册表获取软件的安装路径
string getInstallationPath(){
	REGSAM KEY_T;
	//判断64位决定读注册表的参数
	if (IsWow64() ==TRUE)
	{		
		KEY_T = Key64READ;
	}
	else
	{
		KEY_T = Key32READ;
	}

	string foxpath;
	HKEY hfKey;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		TEXT("SOFTWARE\\Mozilla\\Mozilla Firefox"),//决定遍历哪个子健
		0,
		KEY_T,
		&hfKey) == ERROR_SUCCESS
		)
	{
		foxpath = QueryKey(hfKey);
	}
	RegCloseKey(hfKey);

	string foxTpath = "SOFTWARE\\Mozilla\\Mozilla Firefox\\";
	foxTpath += foxpath;
	foxTpath += "\\Main";
	HKEY hKey;
	TCHAR szProductType[MY_BUFSIZE];
	DWORD dwBufLen = MY_BUFSIZE;
	LONG lRet;
	// 下面是打开注册表, 只有打开后才能做其他操作
	lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, // 要打开的根键
		TEXT(foxTpath.c_str()), // 要打开的子子键（火狐版本67.0.4 (x64 zh-CN)）
		0, // 这个一定要为0
		KEY_T,// 指定打开方式,此为读,32位程序要获取64位的注册表需要在打开键时，添加参数KEY_WOW64_64KEY		
		&hKey); // 用来返回句柄
	if (lRet == ERROR_SUCCESS) // 判断是否打开成功
	{
		// 打开注册表成功
		// 开始查询
		lRet = RegQueryValueEx(hKey, // 打开注册表时返回的句柄
			TEXT("Install Directory"), //要查询的名称,火狐安装目录记录在这里
			NULL, // 一定为NULL或者0
			NULL,
			(LPBYTE)szProductType, // 目录放在这里
			&dwBufLen);
		if (lRet == ERROR_SUCCESS) // 判断是否查询成功
		{
			RegCloseKey(hKey);
			return (char*)szProductType;
		}
		else
		{
			printf("获得安装目录失败\n");
			return Get_failed;
		}
	}
	else {
		printf("打开注册表失败\n");
		return Get_failed;
	}
}

// 通过遍历注册表获取安装路径
string QueryKey(HKEY hKey)
{
	TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
	DWORD    cbName;                   // size of name string
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name
	DWORD    cchClassName = MAX_PATH;  // size of class string
	DWORD    cSubKeys = 0;               // number of subkeys
	DWORD    cbMaxSubKey;              // longest subkey size
	DWORD    cchMaxClass;              // longest class string
	DWORD    cValues;              // number of values for key
	DWORD    cchMaxValue;          // longest value name
	DWORD    cbMaxValueData;       // longest value data
	DWORD    cbSecurityDescriptor; // size of security descriptor
	FILETIME ftLastWriteTime;      // last write time

	DWORD i, retCode;

	TCHAR  achValue[MAX_VALUE_NAME];
	DWORD cchValue = MAX_VALUE_NAME;

	// Get the class name and the value count.
	retCode = RegQueryInfoKey(
		hKey,                    // key handle
		achClass,                // buffer for class name
		&cchClassName,           // size of class string
		NULL,                    // reserved
		&cSubKeys,               // number of subkeys
		&cbMaxSubKey,            // longest subkey size
		&cchMaxClass,            // longest class string
		&cValues,                // number of values for this key
		&cchMaxValue,            // longest value name
		&cbMaxValueData,         // longest value data
		&cbSecurityDescriptor,   // security descriptor
		&ftLastWriteTime);       // last write time

	// Enumerate the subkeys, until RegEnumKeyEx fails.

	if (cSubKeys)
	{
		printf("\nNumber of subkeys: %d\n", cSubKeys);

		for (i = 0; i < cSubKeys; i++)
		{
			cbName = MAX_KEY_LENGTH;
			retCode = RegEnumKeyEx(hKey, i,
				achKey,
				&cbName,
				NULL,
				NULL,
				NULL,
				&ftLastWriteTime);
			if (retCode == ERROR_SUCCESS)
			{
				printf(TEXT("(%d) %s\n"), i + 1, achKey);
				return achKey;
			}
		}
	}

	// Enumerate the key values.
	//遍历子健下的键值
// 	if (cValues)
// 	{
// 		printf("\nNumber of values: %d\n", cValues);
// 
// 		for (i = 0, retCode = ERROR_SUCCESS; i < cValues; i++)
// 		{
// 			cchValue = MAX_VALUE_NAME;
// 			achValue[0] = '\0';
// 			retCode = RegEnumValue(hKey, i,
// 				achValue,
// 				&cchValue,
// 				NULL,
// 				NULL,
// 				NULL,
// 				NULL);
// 
// 			if (retCode == ERROR_SUCCESS)
// 			{
// 				printf(TEXT("(%d) %s\n"), i + 1, achValue);
// 			}
// 		}
// 	}
}
