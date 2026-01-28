#define _CRT_SECURE_NO_WARNINGS


#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <intrin.h>



typedef NTSTATUS(NTAPI* NtContinue_t)(PCONTEXT, BOOLEAN);
typedef VOID(NTAPI* RtlCaptureContext_t)(PCONTEXT);



#define MAGIC_HOUR      3
#define MAGIC_MINUTE    33
#define MAGIC_SECOND    37
#define SLEEP_MS        5000
#define HINT_DELAY_MS   2000


 
const char* g_secretFlag = "CTF{Ekk0_X0R_T1m3_B4s3d_Ch4ll3ng3}";



char g_selfPath[MAX_PATH] = { 0 };
PVOID g_imageBase = NULL;
DWORD g_imageSize = 0;

/* XOR key for Ekko encryption - solver needs to find this! */
DWORD g_xorKey = 0xDEAD0A55;



typedef struct _EKKO_ROP {
    NtContinue_t    pNtContinue;
    FARPROC         pVirtualProtect;
    FARPROC         pWaitForSingleObject;
    FARPROC         pSetEvent;

    DWORD           xorKey;

    PVOID           imageBase;
    DWORD           imageSize;

    HANDLE          hEvent;
    HANDLE          hDelayEvent;
    HANDLE          hTimerQueue;

    DWORD           oldProtect;
    DWORD           sleepTime;

    CONTEXT         ctx[6];

} EKKO_ROP, * PEKKO_ROP;

PEKKO_ROP g_pRop = NULL;


void XorEncryptDecrypt(PVOID buffer, DWORD size, DWORD key) {
    BYTE* ptr = (BYTE*)buffer;
    BYTE* keyBytes = (BYTE*)&key;

    for (DWORD i = 0; i < size; i++) {
        ptr[i] ^= keyBytes[i % 4];
    }
}

VOID CALLBACK XorTimerCallback(PVOID param, BOOLEAN fired) {
    PEKKO_ROP pRop = (PEKKO_ROP)param;
    XorEncryptDecrypt(pRop->imageBase, pRop->imageSize, pRop->xorKey);
}


void GetModuleInfo(void) {
    HMODULE hModule = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);

    g_imageBase = (PVOID)hModule;
    g_imageSize = ntHeaders->OptionalHeader.SizeOfImage;
}



void InitRopContext(PCONTEXT ctx, PCONTEXT baseCtx, PVOID funcAddr,
    PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4) {
    memcpy(ctx, baseCtx, sizeof(CONTEXT));
    ctx->Rip = (DWORD64)funcAddr;
    ctx->Rcx = (DWORD64)arg1;
    ctx->Rdx = (DWORD64)arg2;
    ctx->R8 = (DWORD64)arg3;
    ctx->R9 = (DWORD64)arg4;
    ctx->Rsp &= ~0xFULL;
    ctx->Rsp -= 8;
}



BOOL EkkoSleep(DWORD dwMilliseconds) {
    HMODULE hNtdll = NULL;
    HMODULE hKernel32 = NULL;
    CONTEXT ctxBase = { 0 };
    HANDLE hTimers[4] = { 0 };
    int i;

    g_pRop = (PEKKO_ROP)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(EKKO_ROP));
    if (!g_pRop) {
        Sleep(dwMilliseconds);
        return FALSE;
    }

    hNtdll = GetModuleHandleA("ntdll.dll");
    hKernel32 = GetModuleHandleA("kernel32.dll");

    g_pRop->pNtContinue = (NtContinue_t)GetProcAddress(hNtdll, "NtContinue");
    g_pRop->pVirtualProtect = GetProcAddress(hKernel32, "VirtualProtect");
    g_pRop->pWaitForSingleObject = GetProcAddress(hKernel32, "WaitForSingleObject");
    g_pRop->pSetEvent = GetProcAddress(hKernel32, "SetEvent");

    if (!g_pRop->pNtContinue || !g_pRop->pVirtualProtect ||
        !g_pRop->pWaitForSingleObject || !g_pRop->pSetEvent) {
        HeapFree(GetProcessHeap(), 0, g_pRop);
        g_pRop = NULL;
        Sleep(dwMilliseconds);
        return FALSE;
    }


    g_pRop->xorKey = g_xorKey;
    g_pRop->imageBase = g_imageBase;
    g_pRop->imageSize = g_imageSize;
    g_pRop->sleepTime = dwMilliseconds;


    g_pRop->hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_pRop->hDelayEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_pRop->hTimerQueue = CreateTimerQueue();

    if (!g_pRop->hEvent || !g_pRop->hDelayEvent || !g_pRop->hTimerQueue) {
        if (g_pRop->hEvent) CloseHandle(g_pRop->hEvent);
        if (g_pRop->hDelayEvent) CloseHandle(g_pRop->hDelayEvent);
        if (g_pRop->hTimerQueue) DeleteTimerQueue(g_pRop->hTimerQueue);
        HeapFree(GetProcessHeap(), 0, g_pRop);
        g_pRop = NULL;
        Sleep(dwMilliseconds);
        return FALSE;
    }


    RtlCaptureContext_t pRtlCaptureContext = (RtlCaptureContext_t)
        GetProcAddress(hNtdll, "RtlCaptureContext");
    ctxBase.ContextFlags = CONTEXT_FULL;
    pRtlCaptureContext(&ctxBase);

    printf("  [*] Building ROP chain (XOR encryption)...\n");
    printf("  [*] XOR Key: 0x%08lX (you need to find this!)\n\n", g_pRop->xorKey);

 

    InitRopContext(&g_pRop->ctx[0], &ctxBase, g_pRop->pVirtualProtect,
        g_imageBase, (PVOID)(DWORD_PTR)g_imageSize,
        (PVOID)PAGE_READWRITE, &g_pRop->oldProtect);

    InitRopContext(&g_pRop->ctx[1], &ctxBase, g_pRop->pWaitForSingleObject,
        g_pRop->hDelayEvent, (PVOID)(DWORD_PTR)dwMilliseconds,
        NULL, NULL);


    InitRopContext(&g_pRop->ctx[2], &ctxBase, g_pRop->pVirtualProtect,
        g_imageBase, (PVOID)(DWORD_PTR)g_imageSize,
        (PVOID)PAGE_EXECUTE_READWRITE, &g_pRop->oldProtect);


    InitRopContext(&g_pRop->ctx[3], &ctxBase, g_pRop->pSetEvent,
        g_pRop->hEvent, NULL, NULL, NULL);


    DWORD oldProt;
    VirtualProtect(g_imageBase, g_imageSize, PAGE_READWRITE, &oldProt);

    printf("  [*] XOR encrypting image...\n");
    XorEncryptDecrypt(g_imageBase, g_imageSize, g_pRop->xorKey);

 

    for (i = 0; i < 4; i++) {
        CreateTimerQueueTimer(&hTimers[i], g_pRop->hTimerQueue,
            (WAITORTIMERCALLBACK)g_pRop->pNtContinue,
            &g_pRop->ctx[i], 0, 0, WT_EXECUTEINTIMERTHREAD);
    }

    printf("  [*] Sleeping (encrypted)...\n");

    WaitForSingleObject(g_pRop->hEvent, INFINITE);

    printf("  [*] XOR decrypting image...\n");
    XorEncryptDecrypt(g_imageBase, g_imageSize, g_pRop->xorKey);

    VirtualProtect(g_imageBase, g_imageSize, oldProt, &oldProt);

    printf("  [*] Decrypted. Resuming.\n\n");

    for (i = 0; i < 4; i++) {
        if (hTimers[i]) DeleteTimerQueueTimer(g_pRop->hTimerQueue, hTimers[i], NULL);
    }
    DeleteTimerQueue(g_pRop->hTimerQueue);
    CloseHandle(g_pRop->hEvent);
    CloseHandle(g_pRop->hDelayEvent);
    HeapFree(GetProcessHeap(), 0, g_pRop);
    g_pRop = NULL;

    return TRUE;
}



void SelfDestruct(void) {
    printf("\n  [!] SELF-DESTRUCTING...\n");

    if (g_imageBase && g_imageSize) {
        DWORD oldProt;
        VirtualProtect(g_imageBase, g_imageSize, PAGE_READWRITE, &oldProt);
        SecureZeroMemory(g_imageBase, g_imageSize);
    }

    char tempPath[MAX_PATH], batPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    snprintf(batPath, MAX_PATH, "%s\\d%lu.bat", tempPath, GetCurrentProcessId());

    FILE* f = fopen(batPath, "w");
    if (f) {
        fprintf(f, "@echo off\n:l\ndel \"%s\">nul 2>&1\nif exist \"%s\" goto l\ndel \"%%~f0\"\n",
            g_selfPath, g_selfPath);
        fclose(f);

        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "cmd /c \"%s\"", batPath);
        CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    printf("  [X] Goodbye.\n");
    ExitProcess(0);
}

BOOL CheckTimeWithHints(void) {
    SYSTEMTIME st;
    GetLocalTime(&st);

    printf("\r  [*] Time: %02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
    fflush(stdout);

    BOOL hourMatch = (st.wHour == MAGIC_HOUR);
    BOOL minuteMatch = (st.wMinute == MAGIC_MINUTE);
    BOOL secondMatch = (st.wSecond == MAGIC_SECOND);


    if (hourMatch) {
        fflush(stdout);
        Sleep(HINT_DELAY_MS);
    }

    if (minuteMatch) {
        fflush(stdout);
        Sleep(HINT_DELAY_MS);
    }

    if (secondMatch) {
        fflush(stdout);
        Sleep(HINT_DELAY_MS);
    }

    if (hourMatch && minuteMatch && secondMatch) {
        VulnerableInput();
        SelfDestruct();
        return TRUE; 
    }

    return FALSE;
}




void VulnerableInput(void) {
    char buffer[256];

    volatile DWORD keyOnStack = g_xorKey;
    volatile DWORD marker1 = 0x41414141;
    volatile DWORD marker2 = 0x42424242;

    printf("\n  Dog dancing name dancer : ");
    fflush(stdout);

    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        buffer[strcspn(buffer, "\n")] = 0;

        printf(" dah ~ (0-0) ~");

        printf(buffer);

        printf("\n\n");
    }

    if (marker1 == 0 || marker2 == 0 || keyOnStack == 0) {
        printf("  (never printed)\n");
    }
}



BOOL IsBeingDebugged(void) {
    if (IsDebuggerPresent()) return TRUE;

    BOOL remoteDbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDbg);
    if (remoteDbg) return TRUE;

    return FALSE;
}

int main(int argc, char* argv[]) {
    GetModuleFileNameA(NULL, g_selfPath, MAX_PATH);
    GetModuleInfo();
 
    printf("2 second delay for goats\n");


    if (IsBeingDebugged()) {
        printf("  [!] Debugger detected! gay destroyed\n");
        SelfDestruct();
    }

    printf("  [*] Entering main loop...\n\n");

    int iter = 0;
    while (1) {
        iter++;

        if (iter > 1 && IsBeingDebugged()) {
            SelfDestruct();
        }
        CheckTimeWithHints();

        printf("\n  [*] Entering Ekko sleep...\n\n");
        EkkoSleep(SLEEP_MS);
    }

    return 0;
}