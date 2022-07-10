#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <math.h>
#include "Windows.h"


float ShannonEntropy(char* data, int size) {
    float entropy = 0;
    std::map<char, long> counts;
    for (int i = 0; i != size; i++) {
        counts[data[i]]++;
    }
    
    for (int i = 0; i != counts.size(); i++) {
        float p_x = (float)counts[i] / size;
        if (p_x > 0) entropy -= p_x * log2(p_x);
    }
    return entropy;
}

int main()
{
    std::cout << "Enter PE location: ";
    wchar_t stringEXE[128];
    wchar_t stringICO[128];
    std::wcin >> stringEXE;
    std::cout << "Enter ICO location: ";
    std::wcin >> stringICO;
    HANDLE file = CreateFile(stringEXE, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE icon = CreateFile(stringICO, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD size = GetFileSize(file, NULL);
    DWORD sizeICO = GetFileSize(icon, NULL);
    DWORD bytesReadFile, bytesReadIco;
    PVOID pointer = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
    PVOID pIco = VirtualAlloc(NULL, sizeICO, MEM_COMMIT, PAGE_READWRITE);
    HANDLE fileMap = CreateFileMapping(file, NULL, PAGE_READONLY, NULL, size, NULL);
    HANDLE icoMap = CreateFileMapping(icon, NULL, PAGE_READONLY, NULL, sizeICO, NULL);
    char* bytesExe = (char*)MapViewOfFile(fileMap, FILE_MAP_READ, NULL, NULL, NULL);
    char* bytesIco = (char*)MapViewOfFile(icoMap, FILE_MAP_READ, NULL, NULL, NULL);
    ReadFile(icon, pIco, sizeICO, &bytesReadIco, NULL);
    ReadFile(file, pointer, size, &bytesReadFile, NULL);
    CloseHandle(file);
    CloseHandle(icon);
    std::vector<std::string> libname;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(PCHAR(pointer) + PIMAGE_DOS_HEADER(pointer)->e_lfanew); //NT HEADER
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt); //.text section
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = {}; // POINTER TO .idata
    DWORD importRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress; // RVA of import section
    for (int i = 0; i != nt->FileHeader.NumberOfSections; i++) {
        if (importRVA >= section->VirtualAddress && importRVA < section->VirtualAddress + section->Misc.VirtualSize) {
            pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)pointer + (importRVA - section->VirtualAddress + section->PointerToRawData));
            break;
        }
        section++;
    }
    //get into .idata section and get pointer to IMAGE_IMPORT_DESCRIPTOR
    section = IMAGE_FIRST_SECTION(nt); // section is .text
    std::cout << "Imported libraries (dll): "<<std::endl;
    for (int i = 0; pImportDescriptor->Name != NULL;pImportDescriptor++, i++) {
        DWORD currentRVA = pImportDescriptor->Name; // get RVA of current name library
        std::string temp;
        for (int j = 0; j != nt->FileHeader.NumberOfSections; j++) {
            if (currentRVA >= section->VirtualAddress && currentRVA < section->VirtualAddress + section->Misc.VirtualSize) {
                temp = (PCHAR)((DWORD_PTR)pointer + (currentRVA - section->VirtualAddress + section->PointerToRawData)); // convert it into a char*
                libname.push_back(temp);
                break;
            }
            section++;
        }
        std::cout <<"\t"<< libname[i] << std::endl;
    }
    ///
    unsigned containsW = 0;
    for (int i = 0; i != libname.size(); i++) {
        if (libname[i].find('W') != std::string::npos || libname[i].find('w') != std::string::npos) {
            containsW++;
        }
    }
    std::cout << "Number of libraries that contains letter w in it: " << containsW << std::endl;
    ///replace icon in the executable
    HANDLE image = BeginUpdateResource(stringEXE, FALSE); // reading current exe
    if (image != NULL) { // if success
        if (UpdateResource(image, RT_ICON, MAKEINTRESOURCE(1), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPVOID)pIco, bytesReadIco)) { // if updated
            std::cout << "Icon has been changed successfully!" << std::endl;
            EndUpdateResource(image,FALSE); // then lock it
        }
    }
   /// entropy
    std::cout<<"Entropy of exe file: "<< ShannonEntropy(bytesExe, size)<<std::endl;
    std::cout << "Entropy of ico file: " << ShannonEntropy(bytesIco, sizeICO) << std::endl;
   ///


}