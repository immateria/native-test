/*
 * Helper DLL for win_more.exe's "exitproc" group. ExitProcess first terminates every other thread, then calls each
 * DLL's DLL_PROCESS_DETACH. If a terminated thread held something DllMain needs, what happens?
 *
 * detach_configure(mode, log) chooses what detach waits for; detach_hold(ready) is the body of the other thread,
 * which takes the resource, signals `ready` and sleeps forever (ExitProcess terminates it while it holds it).
 *
 *   0 nothing                       control
 *   1 critical section              held by the terminated thread
 *   2 SRW lock (exclusive)          held by the terminated thread
 *   3 event                         the terminated thread would have set it
 *   4 mutex                         held by the terminated thread (becomes abandoned)
 *   5 slow detach                   no lock, detach sleeps 1500 ms
 *   6 wait for the worker's handle  the usual "stop my thread in DllMain" pattern
 *
 * Build: cl /nologo /O1 /W3 /LD detach_dll.c   (MinGW: gcc -shared -o detach_dll.dll detach_dll.c)
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

static int g_mode;
static HANDLE g_log = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_cs;
static SRWLOCK g_srw = SRWLOCK_INIT;
static HANDLE g_owed, g_mutex, g_worker;

static double now_ms(void) {
  FILETIME ft;
  GetSystemTimePreciseAsFileTime(&ft);
  ULARGE_INTEGER u;
  u.LowPart = ft.dwLowDateTime;
  u.HighPart = ft.dwHighDateTime;
  return (double)u.QuadPart / 10000.0;
}

static void put(const char *what, unsigned long value) {
  char b[160];
  int n = _snprintf(b, sizeof b, "%s t=%.3f value=%lu\n", what, now_ms(), value);
  DWORD w;
  if (g_log != INVALID_HANDLE_VALUE && n > 0) WriteFile(g_log, b, (DWORD)n, &w, NULL);
}

__declspec(dllexport) void detach_configure(int mode, HANDLE log) {
  g_mode = mode;
  g_log = log;
}

__declspec(dllexport) DWORD WINAPI detach_hold(LPVOID ready) {
  g_worker = OpenThread(SYNCHRONIZE, FALSE, GetCurrentThreadId());
  switch (g_mode) {
    case 1: EnterCriticalSection(&g_cs); break;
    case 2: AcquireSRWLockExclusive(&g_srw); break;
    case 4: WaitForSingleObject(g_mutex, INFINITE); break;
    default: break;
  }
  put("worker_holds", (unsigned long)g_mode);
  SetEvent((HANDLE)ready);
  Sleep(INFINITE);
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
  (void)h;
  if (reason == DLL_PROCESS_ATTACH) {
    InitializeCriticalSection(&g_cs);
    g_owed = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_mutex = CreateMutexW(NULL, FALSE, NULL);
  } else if (reason == DLL_PROCESS_DETACH) {
    /* reserved != NULL: the process is terminating (ExitProcess), not FreeLibrary */
    put("detach_start", reserved != NULL);
    DWORD r = 0;
    switch (g_mode) {
      case 1: EnterCriticalSection(&g_cs); LeaveCriticalSection(&g_cs); break;
      case 2: AcquireSRWLockExclusive(&g_srw); ReleaseSRWLockExclusive(&g_srw); break;
      case 3: r = WaitForSingleObject(g_owed, INFINITE); break;
      case 4: r = WaitForSingleObject(g_mutex, INFINITE); break;
      case 5: Sleep(1500); break;
      case 6: r = g_worker ? WaitForSingleObject(g_worker, INFINITE) : 0xFFFFFFFF; break;
      default: break;
    }
    put("detach_end", r);
  }
  return TRUE;
}
