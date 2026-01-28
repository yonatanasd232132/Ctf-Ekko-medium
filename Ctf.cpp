/*
 * PHANTOM v6 - Real Ekko with XOR + Format String Vulnerability
 * 
 * Challenge:
 * - Ekko encrypts the image with XOR during sleep
 * - If you get the time right, we print the key and self-destruct
 * - Time hints: if hour/minute/second is correct, we wait 2 seconds each
 * - Format string vulnerability lets you leak the key
 * - Use the key to decrypt the dumped memory and find the flag
 * 
 * Compile: x86_64-w64-mingw32-gcc phantom_v6.c -o phantom.exe
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <intrin.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *                              NTDLL TYPES
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef NTSTATUS (NTAPI* NtContinue_t)(PCONTEXT, BOOLEAN);
typedef VOID (NTAPI* RtlCaptureContext_t)(PCONTEXT);

/* ═══════════════════════════════════════════════════════════════════════════
 *                              CONFIGURATION
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MAGIC_HOUR      3
#define MAGIC_MINUTE    33
#define MAGIC_SECOND    37
#define SLEEP_MS        5000
#define HINT_DELAY_MS   2000

/* ═══════════════════════════════════════════════════════════════════════════
 *                         THE FLAG (in clear text in code!)
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * This string is in .rdata section. When Ekko encrypts the image,
 * this gets XORed. Solver needs to:
 * 1. Dump memory while encrypted
 * 2. Get the XOR key (via time trigger or format string)
 * 3. XOR the dump to reveal this string
 */
const char* g_secretFlag = "CTF{Ekk0_X0R_T1m3_B4s3d_Ch4ll3ng3}";

/* ═══════════════════════════════════════════════════════════════════════════
 *                              GLOBALS
 * ═══════════════════════════════════════════════════════════════════════════ */

char g_selfPath[MAX_PATH] = {0};
PVOID g_imageBase = NULL;
DWORD g_imageSize = 0;

/* XOR key for Ekko encryption - solver needs to find this! */
DWORD g_xorKey = 0xDEADC0DE;

/* ═══════════════════════════════════════════════════════════════════════════
 *                         EKKO ROP STRUCTURE
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct _EKKO_ROP {
    NtContinue_t    pNtContinue;
    FARPROC         pVirtualProtect;
    FARPROC         pWaitForSingleObject;
    FARPROC         pSetEvent;
    
    /* XOR key copy (survives encryption) */
    DWORD           xorKey;
    
    /* Image info */
    PVOID           imageBase;
    DWORD           imageSize;
    
    /* Synchronization */
    HANDLE          hEvent;
    HANDLE          hDelayEvent;
    HANDLE          hTimerQueue;
    
    DWORD           oldProtect;
    DWORD           sleepTime;
    
    /* ROP contexts */
    CONTEXT         ctx[6];
    
} EKKO_ROP, *PEKKO_ROP;

PEKKO_ROP g_pRop = NULL;

/* ═══════════════════════════════════════════════════════════════════════════
 *                           XOR ENCRYPTION
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Simple XOR encryption - replaces SystemFunction032 (RC4)
 * XORs the entire buffer with a 4-byte key
 */
void XorEncryptDecrypt(PVOID buffer, DWORD size, DWORD key) {
    BYTE* ptr = (BYTE*)buffer;
    BYTE* keyBytes = (BYTE*)&key;
    
    for (DWORD i = 0; i < size; i++) {
        ptr[i] ^= keyBytes[i % 4];
    }
}

/*
 * Timer callback for XOR encryption
 * Called via NtContinue with our CONTEXT
 */
VOID CALLBACK XorTimerCallback(PVOID param, BOOLEAN fired) {
    PEKKO_ROP pRop = (PEKKO_ROP)param;
    XorEncryptDecrypt(pRop->imageBase, pRop->imageSize, pRop->xorKey);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *                           GET MODULE INFO
 * ═══════════════════════════════════════════════════════════════════════════ */

void GetModuleInfo(void) {
    HMODULE hModule = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    
    g_imageBase = (PVOID)hModule;
    g_imageSize = ntHeaders->OptionalHeader.SizeOfImage;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *                         INIT ROP CONTEXT
 * ═══════════════════════════════════════════════════════════════════════════ */

void InitRopContext(PCONTEXT ctx, PCONTEXT baseCtx, PVOID funcAddr,
                    PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4) {
    memcpy(ctx, baseCtx, sizeof(CONTEXT));
    ctx->Rip = (DWORD64)funcAddr;
    ctx->Rcx = (DWORD64)arg1;
    ctx->Rdx = (DWORD64)arg2;
    ctx->R8  = (DWORD64)arg3;
    ctx->R9  = (DWORD64)arg4;
    ctx->Rsp &= ~0xFULL;
    ctx->Rsp -= 8;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *                         REAL EKKO SLEEP (XOR VERSION)
 * ═══════════════════════════════════════════════════════════════════════════ */

BOOL EkkoSleep(DWORD dwMilliseconds) {
    HMODULE hNtdll = NULL;
    HMODULE hKernel32 = NULL;
    CONTEXT ctxBase = {0};
    HANDLE hTimers[4] = {0};
    int i;
    
    /* Allocate ROP structure on heap (survives encryption) */
    g_pRop = (PEKKO_ROP)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(EKKO_ROP));
    if (!g_pRop) {
        Sleep(dwMilliseconds);
        return FALSE;
    }
    
    /* Get function pointers */
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
    
    /* Copy key and image info to heap structure */
    g_pRop->xorKey = g_xorKey;
    g_pRop->imageBase = g_imageBase;
    g_pRop->imageSize = g_imageSize;
    g_pRop->sleepTime = dwMilliseconds;
    
    /* Create events */
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
    
    /* Capture base context */
    RtlCaptureContext_t pRtlCaptureContext = (RtlCaptureContext_t)
        GetProcAddress(hNtdll, "RtlCaptureContext");
    ctxBase.ContextFlags = CONTEXT_FULL;
    pRtlCaptureContext(&ctxBase);
    
    printf("  [*] Building ROP chain (XOR encryption)...\n");
    printf("  [*] XOR Key: 0x%08lX (you need to find this!)\n\n", g_pRop->xorKey);
    
    /* ═══════════════════════════════════════════════════════════════════
     * BUILD ROP CHAIN
     * 
     * ctx[0]: VirtualProtect (make RW)
     * ctx[1]: XOR Encrypt (via callback - we'll do it manually before)
     * ctx[2]: WaitForSingleObject (delay)
     * ctx[3]: SetEvent (signal done)
     * 
     * Note: Since XOR is our function (not in a DLL), we need to do
     * the encrypt/decrypt around the ROP chain, not inside it.
     * ═══════════════════════════════════════════════════════════════════ */
    
    /* Context 0: VirtualProtect (RW) */
    InitRopContext(&g_pRop->ctx[0], &ctxBase, g_pRop->pVirtualProtect,
        g_imageBase, (PVOID)(DWORD_PTR)g_imageSize,
        (PVOID)PAGE_READWRITE, &g_pRop->oldProtect);
    
    /* Context 1: WaitForSingleObject (the delay - encrypted!) */
    InitRopContext(&g_pRop->ctx[1], &ctxBase, g_pRop->pWaitForSingleObject,
        g_pRop->hDelayEvent, (PVOID)(DWORD_PTR)dwMilliseconds,
        NULL, NULL);
    
    /* Context 2: VirtualProtect (restore) */
    InitRopContext(&g_pRop->ctx[2], &ctxBase, g_pRop->pVirtualProtect,
        g_imageBase, (PVOID)(DWORD_PTR)g_imageSize,
        (PVOID)PAGE_EXECUTE_READWRITE, &g_pRop->oldProtect);
    
    /* Context 3: SetEvent (signal completion) */
    InitRopContext(&g_pRop->ctx[3], &ctxBase, g_pRop->pSetEvent,
        g_pRop->hEvent, NULL, NULL, NULL);
    
    /* Make image writable */
    DWORD oldProt;
    VirtualProtect(g_imageBase, g_imageSize, PAGE_READWRITE, &oldProt);
    
    /* XOR ENCRYPT the image */
    printf("  [*] XOR encrypting image...\n");
    XorEncryptDecrypt(g_imageBase, g_imageSize, g_pRop->xorKey);
    
    printf("\n");
    printf("  ╔═══════════════════════════════════════════════════════════╗\n");
    printf("  ║   IMAGE IS NOW XOR ENCRYPTED!                             ║\n");
    printf("  ║   Key: 0x%08lX (stored on heap, survives encryption)    ║\n", g_pRop->xorKey);
    printf("  ╚═══════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    /* Queue timers with NtContinue as callback */
    for (i = 0; i < 4; i++) {
        CreateTimerQueueTimer(&hTimers[i], g_pRop->hTimerQueue,
            (WAITORTIMERCALLBACK)g_pRop->pNtContinue,
            &g_pRop->ctx[i], 0, 0, WT_EXECUTEINTIMERTHREAD);
    }
    
    printf("  [*] Sleeping (encrypted)...\n");
    
    /* Wait for ROP chain to complete */
    WaitForSingleObject(g_pRop->hEvent, INFINITE);
    
    /* XOR DECRYPT the image */
    printf("  [*] XOR decrypting image...\n");
    XorEncryptDecrypt(g_imageBase, g_imageSize, g_pRop->xorKey);
    
    /* Restore protection */
    VirtualProtect(g_imageBase, g_imageSize, oldProt, &oldProt);
    
    printf("  [*] Decrypted. Resuming.\n\n");
    
    /* Cleanup */
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

/* ═══════════════════════════════════════════════════════════════════════════
 *                              SELF DESTRUCT
 * ═══════════════════════════════════════════════════════════════════════════ */

void SelfDestruct(void) {
    printf("\n  [!] SELF-DESTRUCTING...\n");
    
    /* Wipe memory */
    if (g_imageBase && g_imageSize) {
        DWORD oldProt;
        VirtualProtect(g_imageBase, g_imageSize, PAGE_READWRITE, &oldProt);
        SecureZeroMemory(g_imageBase, g_imageSize);
    }
    
    /* Delete ourselves */
    char tempPath[MAX_PATH], batPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    snprintf(batPath, MAX_PATH, "%s\\d%lu.bat", tempPath, GetCurrentProcessId());
    
    FILE* f = fopen(batPath, "w");
    if (f) {
        fprintf(f, "@echo off\n:l\ndel \"%s\">nul 2>&1\nif exist \"%s\" goto l\ndel \"%%~f0\"\n",
                g_selfPath, g_selfPath);
        fclose(f);
        
        STARTUPINFOA si = {sizeof(si)};
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

/* ═══════════════════════════════════════════════════════════════════════════
 *                    TIME CHECK WITH HINTS
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * If hour matches:   wait 2 seconds (hint!)
 * If minute matches: wait 2 seconds (hint!)
 * If second matches: wait 2 seconds (hint!)
 * 
 * This helps solver narrow down the time without brute-forcing all values.
 */

BOOL CheckTimeWithHints(void) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    printf("\r  [*] Time: %02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
    fflush(stdout);
    
    BOOL hourMatch = (st.wHour == MAGIC_HOUR);
    BOOL minuteMatch = (st.wMinute == MAGIC_MINUTE);
    BOOL secondMatch = (st.wSecond == MAGIC_SECOND);
    
    /* Hints: delay if partial match */
    if (hourMatch) {
        printf(" [HOUR OK!]");
        fflush(stdout);
        Sleep(HINT_DELAY_MS);
    }
    
    if (minuteMatch) {
        printf(" [MINUTE OK!]");
        fflush(stdout);
        Sleep(HINT_DELAY_MS);
    }
    
    if (secondMatch) {
        printf(" [SECOND OK!]");
        fflush(stdout);
        Sleep(HINT_DELAY_MS);
    }
    
    /* Full match! */
    if (hourMatch && minuteMatch && secondMatch) {
        printf("\n\n");
        printf("  ╔═══════════════════════════════════════════════════════════╗\n");
        printf("  ║              !! CORRECT TIME !!                           ║\n");
        printf("  ║                                                           ║\n");
        printf("  ║   Here's your reward - the XOR key:                       ║\n");
        printf("  ║                                                           ║\n");
        printf("  ║   KEY: 0x%08lX                                        ║\n", g_xorKey);
        printf("  ║                                                           ║\n");
        printf("  ║   Use this to decrypt a memory dump and find the flag!    ║\n");
        printf("  ╚═══════════════════════════════════════════════════════════╝\n");
        printf("\n");
        
        /* Self-destruct after revealing key */
        SelfDestruct();
        return TRUE;  /* Never reached */
    }
    
    return FALSE;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *                    FORMAT STRING VULNERABILITY
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * This function has a format string vulnerability!
 * The solver can use it to leak the XOR key from the stack.
 * 
 * Usage: Enter something like "%p %p %p %p %p %p %p %p" to leak stack values
 * The XOR key (0xDEADC0DE) will be visible in the output!
 */

void VulnerableInput(void) {
    char buffer[256];
    
    /* Put the key on the stack where it can be leaked */
    volatile DWORD keyOnStack = g_xorKey;
    volatile DWORD marker1 = 0x41414141;
    volatile DWORD marker2 = 0x42424242;
    
    printf("\n  [?] Enter your name for the log: ");
    fflush(stdout);
    
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        /* Remove newline */
        buffer[strcspn(buffer, "\n")] = 0;
        
        printf("  [LOG] User: ");
        
        /* VULNERABILITY: printf with user-controlled format string! */
        printf(buffer);
        
        printf("\n\n");
    }
    
    /* Use the variables so compiler doesn't optimize them away */
    if (marker1 == 0 || marker2 == 0 || keyOnStack == 0) {
        printf("  (never printed)\n");
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *                              ANTI-DEBUG
 * ═══════════════════════════════════════════════════════════════════════════ */

BOOL IsBeingDebugged(void) {
    if (IsDebuggerPresent()) return TRUE;
    
    BOOL remoteDbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDbg);
    if (remoteDbg) return TRUE;
    
    return FALSE;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *                                   MAIN
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char* argv[]) {
    GetModuleFileNameA(NULL, g_selfPath, MAX_PATH);
    GetModuleInfo();
    
    printf("\n");
    printf("  ╔═══════════════════════════════════════════════════════════╗\n");
    printf("  ║                                                           ║\n");
    printf("  ║               P H A N T O M   v6.0                        ║\n");
    printf("  ║                                                           ║\n");
    printf("  ║        [ Ekko + XOR + Time Hints + Format String ]        ║\n");
    printf("  ║                                                           ║\n");
    printf("  ╚═══════════════════════════════════════════════════════════╝\n\n");
    
    printf("  [*] Image Base: %p\n", g_imageBase);
    printf("  [*] Image Size: 0x%lX bytes\n", (unsigned long)g_imageSize);
    printf("  [*] Flag location: %p (encrypted during sleep)\n", g_secretFlag);
    printf("  [*] Target time: ??:??:?? (you need to find it!)\n\n");
    
    printf("  [*] HINTS:\n");
    printf("      - If hour is correct:   2 second delay\n");
    printf("      - If minute is correct: 2 second delay\n");
    printf("      - If second is correct: 2 second delay\n");
    printf("      - Correct time = key revealed + self-destruct\n\n");
    
    if (IsBeingDebugged()) {
        printf("  [!] Debugger detected!\n");
        SelfDestruct();
    }
    
    /* Format string vulnerability - lets solver leak the key! */
    VulnerableInput();
    
    printf("  [*] Entering main loop...\n\n");
    
    int iter = 0;
    while (1) {
        iter++;
        
        if (iter > 1 && IsBeingDebugged()) {
            SelfDestruct();
        }
        
        /* Check time with hints */
        CheckTimeWithHints();
        
        printf("\n  [*] Entering Ekko sleep...\n\n");
        EkkoSleep(SLEEP_MS);
    }
    
    return 0;
}