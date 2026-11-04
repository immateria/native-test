/*
 * Windows process-supervision exploration (C, MSVC or MinGW). Records JSON lines, never asserts.
 * Covers what the Job-object kit does not: console control events (the only graceful stop for console
 * programs), ConPTY, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, WaitForMultipleObjects limits and a job handle's
 * signaled state, registered waits at scale, job IO/network rate control, the child-process policy, crash
 * timing with and without a debugger, the debugger as a "die with my parent" mechanism, and silo creation.
 *
 * Build (from a VS developer prompt):  cl /nologo /O1 /Fe:proc_explore.exe proc_explore.c user32.lib advapi32.lib
 * Run:  proc_explore.exe [ctrl|conpty|parent|wait|rate|mitigation|debug|silo|period|iorate|pipes|pidreuse|all]
 *       (each group runs well inside the 300 s watchdog; "all" may not, so CI runs groups one by one)
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifdef _MSC_VER
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif
#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif
#ifndef PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY
#define PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY 0x0002000E
#endif

#define PROBE "proc_explore"

/* ------------------------------------------------------------------ helpers */
static double abs_ms(void) { /* ms since 1601, comparable across processes */
  FILETIME ft;
  GetSystemTimePreciseAsFileTime(&ft);
  ULARGE_INTEGER u;
  u.LowPart = ft.dwLowDateTime;
  u.HighPart = ft.dwHighDateTime;
  return (double)u.QuadPart / 10000.0;
}

static double qpc_ms(void) {
  LARGE_INTEGER f, c;
  QueryPerformanceFrequency(&f);
  QueryPerformanceCounter(&c);
  return (double)c.QuadPart * 1000.0 / (double)f.QuadPart;
}

typedef VOID(WINAPI *PFN_QueryInterruptTimePrecise)(PULONGLONG);
static double itime_ms(void) { /* the kernel's interrupt-time clock (100 ns units), -1 if unavailable */
  static PFN_QueryInterruptTimePrecise f = NULL;
  static int looked = 0;
  if (!looked) {
    looked = 1;
    HMODULE kb = GetModuleHandleW(L"kernelbase.dll");
    if (kb) f = (PFN_QueryInterruptTimePrecise)(void *)GetProcAddress(kb, "QueryInterruptTimePrecise");
  }
  if (!f) return -1;
  ULONGLONG t = 0;
  f(&t);
  return (double)t / 10000.0;
}

static void emit(const char *kase, const char *fmt, ...) {
  char body[4096];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(body, sizeof body, fmt, ap);
  va_end(ap);
  printf("{\"probe\":\"%s\",\"case\":\"%s\",%s}\n", PROBE, kase, body);
  fflush(stdout);
}

static const char *bstr(int b) { return b ? "true" : "false"; }

static double ft_ms(FILETIME f) { ULARGE_INTEGER u; u.LowPart = f.dwLowDateTime; u.HighPart = f.dwHighDateTime; return (double)u.QuadPart / 10000.0; }

/* kernel exit time of an exited process minus t_ref (both ms since 1601); -1 if it has not exited */
static double exit_after(HANDLE h, double t_ref) {
  FILETIME c, x, k, u;
  if (WaitForSingleObject(h, 0) != WAIT_OBJECT_0 || !GetProcessTimes(h, &c, &x, &k, &u)) return -1;
  return ft_ms(x) - t_ref;
}

static wchar_t g_self[MAX_PATH * 2];
static wchar_t g_tmp[MAX_PATH * 2];

static void init_paths(void) {
  GetModuleFileNameW(NULL, g_self, (DWORD)(sizeof g_self / sizeof g_self[0]));
  wchar_t base[MAX_PATH * 2];
  DWORD n = GetTempPathW((DWORD)(sizeof base / sizeof base[0]), base);
  (void)n;
  swprintf(g_tmp, sizeof g_tmp / sizeof g_tmp[0], L"%lsproc-explore-%lu", base, (unsigned long)GetCurrentProcessId());
  CreateDirectoryW(g_tmp, NULL);
}

static void tmp_file(wchar_t *out, size_t n, const wchar_t *name) { swprintf(out, n, L"%ls\\%ls", g_tmp, name); }

static int read_text(const wchar_t *path, char *buf, size_t cap) {
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) { buf[0] = 0; return -1; }
  DWORD got = 0;
  ReadFile(h, buf, (DWORD)(cap - 1), &got, NULL);
  CloseHandle(h);
  buf[got] = 0;
  return (int)got;
}

static void log_to(HANDLE h, const char *fmt, ...) {
  char b[512];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(b, sizeof b, fmt, ap);
  va_end(ap);
  DWORD w;
  if (h && h != INVALID_HANDLE_VALUE && n > 0) WriteFile(h, b, (DWORD)n, &w, NULL);
}

static HANDLE open_log(const wchar_t *path) {
  return CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

/* Create a child that runs this executable with `args`. attrs may be NULL. */
static BOOL spawn_self(const wchar_t *args, DWORD flags, LPPROC_THREAD_ATTRIBUTE_LIST attrs, PROCESS_INFORMATION *pi, DWORD *err) {
  wchar_t cmd[4096];
  swprintf(cmd, sizeof cmd / sizeof cmd[0], L"\"%ls\" %ls", g_self, args);
  STARTUPINFOEXW si;
  memset(&si, 0, sizeof si);
  si.StartupInfo.cb = sizeof si;
  if (attrs) { si.lpAttributeList = attrs; flags |= EXTENDED_STARTUPINFO_PRESENT; }
  memset(pi, 0, sizeof *pi);
  BOOL ok = CreateProcessW(NULL, cmd, NULL, NULL, FALSE, flags, NULL, NULL, &si.StartupInfo, pi);
  *err = ok ? 0 : GetLastError();
  return ok;
}

static DWORD wait_exit(HANDLE h, DWORD ms, int *exited) {
  DWORD w = WaitForSingleObject(h, ms);
  *exited = w == WAIT_OBJECT_0;
  DWORD code = 0;
  GetExitCodeProcess(h, &code);
  return code;
}

static void kill_close(PROCESS_INFORMATION *pi) {
  if (pi->hProcess) { TerminateProcess(pi->hProcess, 1); WaitForSingleObject(pi->hProcess, 2000); CloseHandle(pi->hProcess); }
  if (pi->hThread) CloseHandle(pi->hThread);
  memset(pi, 0, sizeof *pi);
}

/* "ev=N t=T" lines -> "N@+ms,..." relative to t_ref; returns number of events. */
static int events_text(const wchar_t *path, double t_ref, char *out, size_t cap, int *saw_ready) {
  char buf[4096];
  out[0] = 0;
  *saw_ready = 0;
  if (read_text(path, buf, sizeof buf) <= 0) return 0;
  int count = 0;
  size_t len = 0;
  char *line = strtok(buf, "\n");
  while (line) {
    unsigned long ev;
    double t;
    if (strstr(line, "ready")) *saw_ready = 1;
    if (sscanf(line, "ev=%lu t=%lf", &ev, &t) == 2) {
      len += (size_t)snprintf(out + len, cap - len, "%s%lu@%+.0fms", count ? "," : "", ev, t - t_ref);
      count++;
    }
    line = strtok(NULL, "\n");
  }
  return count;
}

static int wait_ready(const wchar_t *path, HANDLE proc, DWORD ms) {
  double end = abs_ms() + ms;
  char buf[2048];
  while (abs_ms() < end) {
    if (read_text(path, buf, sizeof buf) > 0 && strstr(buf, "ready")) return 1;
    if (WaitForSingleObject(proc, 0) == WAIT_OBJECT_0) return 0;
    Sleep(20);
  }
  return 0;
}

static int parent_has_console(void) {
  DWORD pids[8];
  return GetConsoleProcessList(pids, 8) > 0;
}

/* ------------------------------------------------------------------ children */
static HANDLE g_log = INVALID_HANDLE_VALUE;

static BOOL WINAPI h_true(DWORD ev) { log_to(g_log, "ev=%lu t=%.3f\n", (unsigned long)ev, abs_ms()); return TRUE; }
static BOOL WINAPI h_false(DWORD ev) { log_to(g_log, "ev=%lu t=%.3f\n", (unsigned long)ev, abs_ms()); return FALSE; }
static BOOL WINAPI h_exit(DWORD ev) { log_to(g_log, "ev=%lu t=%.3f\n", (unsigned long)ev, abs_ms()); ExitProcess(42); return TRUE; }
static BOOL WINAPI h_swallow(DWORD ev) { (void)ev; return TRUE; }

static int child_ctrl(const wchar_t *mode, const wchar_t *logpath) {
  g_log = open_log(logpath);
  if (wcscmp(mode, L"handler_true") == 0) SetConsoleCtrlHandler(h_true, TRUE);
  else if (wcscmp(mode, L"handler_false") == 0) SetConsoleCtrlHandler(h_false, TRUE);
  else if (wcscmp(mode, L"handler_exit") == 0) SetConsoleCtrlHandler(h_exit, TRUE);
  else if (wcscmp(mode, L"ignore") == 0) SetConsoleCtrlHandler(NULL, TRUE);
  DWORD pids[4];
  log_to(g_log, "ready console_window=%d console_processes=%lu\n", GetConsoleWindow() != NULL, (unsigned long)GetConsoleProcessList(pids, 4));
  Sleep(30000);
  return 0;
}

static int child_sender(const wchar_t *kind, DWORD pid, const wchar_t *resultpath) {
  SetConsoleCtrlHandler(h_swallow, TRUE);
  FreeConsole();
  BOOL a = AttachConsole(pid);
  DWORD ae = a ? 0 : GetLastError();
  SetConsoleCtrlHandler(h_swallow, TRUE);
  BOOL g = FALSE;
  DWORD ge = 0;
  if (a) {
    g = GenerateConsoleCtrlEvent(wcscmp(kind, L"break") == 0 ? CTRL_BREAK_EVENT : CTRL_C_EVENT, 0);
    ge = g ? 0 : GetLastError();
    Sleep(300);
    FreeConsole();
  }
  HANDLE h = open_log(resultpath);
  log_to(h, "attach_ok=%d attach_err=%lu generate_ok=%d generate_err=%lu\n", a != FALSE, (unsigned long)ae, g != FALSE, (unsigned long)ge);
  if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
  return 0;
}

static int child_spawn_try(const wchar_t *resultpath) {
  HANDLE h = open_log(resultpath);
  wchar_t cmd[] = L"cmd.exe /c exit 0";
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  memset(&si, 0, sizeof si);
  si.cb = sizeof si;
  BOOL ok = CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
  DWORD e = ok ? 0 : GetLastError();
  log_to(h, "ready create_ok=%d err=%lu\n", ok != FALSE, (unsigned long)e);
  if (ok) { WaitForSingleObject(pi.hProcess, 3000); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
  return 0;
}

static int child_write(const wchar_t *path, int count) {
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);
  if (h == INVALID_HANDLE_VALUE) return 2;
  void *buf = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); /* page-aligned, as NO_BUFFERING needs */
  if (!buf) return 4;
  memset(buf, 'w', 4096);
  for (int i = 0; i < count; i++) {
    DWORD w;
    if (!WriteFile(h, buf, 4096, &w, NULL)) return 3;
  }
  CloseHandle(h);
  DeleteFileW(path);
  return 0;
}

static int child_crash(int nogpfault) {
  if (nogpfault) SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
  volatile int *p = NULL;
  *p = 1;
  return 0;
}

/* a debugger that owns one sleeping child; used to test "debuggee dies with its debugger" */
static int child_debugger(const wchar_t *logpath, int kill_on_exit) {
  HANDLE log = open_log(logpath);
  BOOL early = TRUE;
  DWORD early_err = 0;
  if (kill_on_exit == 2) { early = DebugSetProcessKillOnExit(FALSE); early_err = early ? 0 : GetLastError(); } /* before any debug object exists */
  PROCESS_INFORMATION pi;
  DWORD err;
  if (!spawn_self(L"--child-sleep 60000", DEBUG_ONLY_THIS_PROCESS, NULL, &pi, &err)) {
    log_to(log, "ready spawn_failed=%lu\n", (unsigned long)err);
    return 1;
  }
  BOOL set = TRUE;
  DWORD set_err = 0;
  if (kill_on_exit == 0) { set = DebugSetProcessKillOnExit(FALSE); set_err = set ? 0 : GetLastError(); }
  log_to(log, "ready child=%lu early_call_ok=%d early_err=%lu late_call_ok=%d late_err=%lu\n", (unsigned long)pi.dwProcessId, early != FALSE,
         (unsigned long)early_err, set != FALSE, (unsigned long)set_err);
  DEBUG_EVENT de;
  for (;;) {
    if (!WaitForDebugEvent(&de, INFINITE)) break;
    DWORD cont = DBG_CONTINUE;
    if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) cont = DBG_EXCEPTION_NOT_HANDLED;
    ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont);
  }
  return 0;
}

/* ------------------------------------------------------------------ ctrl events */
typedef struct {
  const char *name;
  DWORD flags;
  const wchar_t *child_mode;
  const char *send; /* break_pid | ctrlc_pid | attach_ctrlc | attach_break */
} ctrl_case_t;

static void run_ctrl_case(const ctrl_case_t *c, int idx) {
  wchar_t log[MAX_PATH * 2], res[MAX_PATH * 2], args[1024];
  wchar_t lname[64], rname[64];
  swprintf(lname, 64, L"ctrl-%d.log", idx);
  swprintf(rname, 64, L"ctrl-%d.res", idx);
  tmp_file(log, MAX_PATH * 2, lname);
  tmp_file(res, MAX_PATH * 2, rname);
  DeleteFileW(log); DeleteFileW(res);
  swprintf(args, 1024, L"--child-ctrl %ls \"%ls\"", c->child_mode, log);
  PROCESS_INFORMATION pi;
  DWORD err;
  if (!spawn_self(args, c->flags, NULL, &pi, &err)) {
    emit(c->name, "\"spawn_error\":%lu", (unsigned long)err);
    return;
  }
  int ready = wait_ready(log, pi.hProcess, 6000);
  int exited0;
  DWORD early = wait_exit(pi.hProcess, 0, &exited0);
  if (!ready) {
    emit(c->name, "\"child_ready\":false,\"child_exited_early\":%s,\"child_exit_code\":\"0x%08lX\",\"note\":\"child never reached its ready line\"",
         bstr(exited0), (unsigned long)early);
    kill_close(&pi);
    return;
  }
  char info[256] = "";
  { char b[1024]; if (read_text(log, b, sizeof b) > 0) { char *e = strchr(b, '\n'); if (e) *e = 0; snprintf(info, sizeof info, "%s", b); } }
  double t_send = abs_ms();
  char send_result[256] = "";
  if (strcmp(c->send, "break_pid") == 0 || strcmp(c->send, "ctrlc_pid") == 0) {
    BOOL ok = GenerateConsoleCtrlEvent(strcmp(c->send, "break_pid") == 0 ? CTRL_BREAK_EVENT : CTRL_C_EVENT, pi.dwProcessId);
    DWORD ge = ok ? 0 : GetLastError();
    snprintf(send_result, sizeof send_result, "generate_ok=%d generate_err=%lu", ok != FALSE, (unsigned long)ge);
  } else {
    wchar_t sargs[1024];
    swprintf(sargs, 1024, L"--sender %ls %lu \"%ls\"", strcmp(c->send, "attach_break") == 0 ? L"break" : L"ctrlc", (unsigned long)pi.dwProcessId, res);
    PROCESS_INFORMATION sp;
    DWORD se;
    if (spawn_self(sargs, 0, NULL, &sp, &se)) {
      int sx;
      wait_exit(sp.hProcess, 8000, &sx);
      CloseHandle(sp.hProcess); CloseHandle(sp.hThread);
      read_text(res, send_result, sizeof send_result);
      send_result[strcspn(send_result, "\r\n")] = 0;
    } else {
      snprintf(send_result, sizeof send_result, "sender_spawn_error=%lu", (unsigned long)se);
    }
  }
  int exited;
  DWORD code = wait_exit(pi.hProcess, 2500, &exited);
  char evs[512];
  int saw;
  int n = events_text(log, t_send, evs, sizeof evs, &saw);
  emit(c->name,
       "\"parent_has_console\":%s,\"child\":\"%s\",\"send\":\"%s\",\"send_result\":\"%s\",\"events_received\":%d,\"events\":\"%s\","
       "\"child_exited_within_2500ms\":%s,\"child_exit_code\":\"0x%08lX\",\"ms_to_exit\":%.0f",
       bstr(parent_has_console()), info, c->send, send_result, n, evs, bstr(exited), (unsigned long)(exited ? code : 0),
       exit_after(pi.hProcess, t_send));
  kill_close(&pi);
}

static void probe_ctrl(void) {
  static const ctrl_case_t cases[] = {
    {"ctrl_new_process_group__CTRL_BREAK_to_pid__handler_returns_true", CREATE_NEW_PROCESS_GROUP, L"handler_true", "break_pid"},
    {"ctrl_new_process_group__CTRL_BREAK_to_pid__no_handler", CREATE_NEW_PROCESS_GROUP, L"default", "break_pid"},
    {"ctrl_new_process_group__CTRL_BREAK_to_pid__handler_returns_false", CREATE_NEW_PROCESS_GROUP, L"handler_false", "break_pid"},
    {"ctrl_new_process_group__CTRL_BREAK_to_pid__handler_exits_42", CREATE_NEW_PROCESS_GROUP, L"handler_exit", "break_pid"},
    {"ctrl_new_process_group__CTRL_C_to_pid", CREATE_NEW_PROCESS_GROUP, L"handler_true", "ctrlc_pid"},
    {"ctrl_new_console__attach_and_CTRL_C__handler_returns_true", CREATE_NEW_CONSOLE, L"handler_true", "attach_ctrlc"},
    {"ctrl_new_console__attach_and_CTRL_C__no_handler", CREATE_NEW_CONSOLE, L"default", "attach_ctrlc"},
    {"ctrl_new_console__attach_and_CTRL_C__ignored_by_child", CREATE_NEW_CONSOLE, L"ignore", "attach_ctrlc"},
    {"ctrl_new_console__attach_and_CTRL_BREAK__handler_returns_true", CREATE_NEW_CONSOLE, L"handler_true", "attach_break"},
    {"ctrl_new_console__attach_and_CTRL_BREAK__no_handler", CREATE_NEW_CONSOLE, L"default", "attach_break"},
    {"ctrl_new_console_and_new_process_group__attach_and_CTRL_C", CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP, L"handler_true", "attach_ctrlc"},
    {"ctrl_no_window__attach_and_CTRL_C__handler_returns_true", CREATE_NO_WINDOW, L"handler_true", "attach_ctrlc"},
    {"ctrl_detached_process__attach_and_CTRL_C", DETACHED_PROCESS, L"handler_true", "attach_ctrlc"},
  };
  emit("ctrl_environment", "\"parent_has_console\":%s,\"console_window\":%s", bstr(parent_has_console()), bstr(GetConsoleWindow() != NULL));
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) run_ctrl_case(&cases[i], (int)i);
}

/* ------------------------------------------------------------------ ConPTY */
typedef HRESULT(WINAPI *PFN_CreatePseudoConsole)(COORD, HANDLE, HANDLE, DWORD, void **);
typedef void(WINAPI *PFN_ClosePseudoConsole)(void *);

static DWORD WINAPI drain_thread(LPVOID p) {
  HANDLE h = (HANDLE)p;
  char b[4096];
  DWORD n;
  while (ReadFile(h, b, sizeof b, &n, NULL) && n) {}
  return 0;
}

typedef struct { PFN_ClosePseudoConsole fn; void *hpc; double ms; } close_job_t;
static DWORD WINAPI close_thread(LPVOID p) {
  close_job_t *j = (close_job_t *)p;
  double t = abs_ms();
  j->fn(j->hpc);
  j->ms = abs_ms() - t;
  return 0;
}

static LPPROC_THREAD_ATTRIBUTE_LIST make_attrs(DWORD_PTR attr, void *value, SIZE_T size) {
  SIZE_T sz = 0;
  InitializeProcThreadAttributeList(NULL, 1, 0, &sz);
  LPPROC_THREAD_ATTRIBUTE_LIST l = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sz);
  if (!l) return NULL;
  if (!InitializeProcThreadAttributeList(l, 1, 0, &sz)) return NULL;
  if (!UpdateProcThreadAttribute(l, 0, attr, value, size, NULL, NULL)) { DeleteProcThreadAttributeList(l); return NULL; }
  return l;
}

static void run_conpty_case(const char *name, const wchar_t *child_mode, const char *action, int idx) {
  HMODULE k = GetModuleHandleW(L"kernel32.dll");
  PFN_CreatePseudoConsole create = (PFN_CreatePseudoConsole)(void *)GetProcAddress(k, "CreatePseudoConsole");
  PFN_ClosePseudoConsole closepc = (PFN_ClosePseudoConsole)(void *)GetProcAddress(k, "ClosePseudoConsole");
  if (!create || !closepc) { emit(name, "\"unsupported\":\"CreatePseudoConsole not exported by kernel32\""); return; }
  wchar_t log[MAX_PATH * 2], res[MAX_PATH * 2], args[1024], ln[64], rn[64];
  swprintf(ln, 64, L"conpty-%d.log", idx);
  swprintf(rn, 64, L"conpty-%d.res", idx);
  tmp_file(log, MAX_PATH * 2, ln);
  tmp_file(res, MAX_PATH * 2, rn);
  DeleteFileW(log); DeleteFileW(res);
  HANDLE in_r, in_w, out_r, out_w;
  CreatePipe(&in_r, &in_w, NULL, 0);
  CreatePipe(&out_r, &out_w, NULL, 0);
  COORD size = {80, 25};
  void *hpc = NULL;
  HRESULT hr = create(size, in_r, out_w, 0, &hpc);
  if (FAILED(hr)) { emit(name, "\"create_pseudoconsole_hresult\":\"0x%08lX\"", (unsigned long)hr); return; }
  CloseHandle(in_r); CloseHandle(out_w);
  HANDLE reader = CreateThread(NULL, 0, drain_thread, out_r, 0, NULL);
  LPPROC_THREAD_ATTRIBUTE_LIST attrs = make_attrs(PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, hpc, sizeof(hpc));
  swprintf(args, 1024, L"--child-ctrl %ls \"%ls\"", child_mode, log);
  PROCESS_INFORMATION pi;
  DWORD err;
  if (!attrs || !spawn_self(args, 0, attrs, &pi, &err)) {
    emit(name, "\"spawn_error\":%lu,\"attrs_ok\":%s", (unsigned long)(attrs ? err : GetLastError()), bstr(attrs != NULL));
    closepc(hpc);
    return;
  }
  int ready = wait_ready(log, pi.hProcess, 8000);
  char info[256] = "";
  { char b[1024]; if (read_text(log, b, sizeof b) > 0) { char *e = strchr(b, '\n'); if (e) *e = 0; snprintf(info, sizeof info, "%s", b); } }
  double t_send = abs_ms();
  char what[256] = "";
  double close_ms = -1;
  int close_returned = 1;
  if (!ready) {
    snprintf(what, sizeof what, "child not ready");
  } else if (strcmp(action, "ctrl_c") == 0) {
    DWORD w;
    BOOL ok = WriteFile(in_w, "\x03", 1, &w, NULL);
    snprintf(what, sizeof what, "wrote 0x03 to the pty input: ok=%d", ok != FALSE);
  } else if (strcmp(action, "attach_break") == 0) {
    wchar_t sargs[1024];
    swprintf(sargs, 1024, L"--sender break %lu \"%ls\"", (unsigned long)pi.dwProcessId, res);
    PROCESS_INFORMATION sp;
    DWORD se;
    if (spawn_self(sargs, 0, NULL, &sp, &se)) {
      int sx;
      wait_exit(sp.hProcess, 8000, &sx);
      CloseHandle(sp.hProcess); CloseHandle(sp.hThread);
      read_text(res, what, sizeof what);
      what[strcspn(what, "\r\n")] = 0;
    }
  } else if (strcmp(action, "close") == 0) {
    close_job_t cj = {closepc, hpc, -1};
    HANDLE t = CreateThread(NULL, 0, close_thread, &cj, 0, NULL);
    close_returned = WaitForSingleObject(t, 15000) == WAIT_OBJECT_0;
    close_ms = cj.ms;
    CloseHandle(t);
    hpc = NULL;
    snprintf(what, sizeof what, "ClosePseudoConsole called");
  }
  int exited;
  DWORD code = wait_exit(pi.hProcess, strcmp(action, "close") == 0 ? 12000 : 2500, &exited);
  char evs[512];
  int saw;
  int n = events_text(log, t_send, evs, sizeof evs, &saw);
  emit(name,
       "\"child\":\"%s\",\"action\":\"%s\",\"action_result\":\"%s\",\"close_returned\":%s,\"close_ms\":%.0f,\"events_received\":%d,\"events\":\"%s\","
       "\"child_exited\":%s,\"child_exit_code\":\"0x%08lX\",\"ms_to_exit\":%.0f",
       info, action, what, bstr(close_returned), close_ms, n, evs, bstr(exited), (unsigned long)(exited ? code : 0), exit_after(pi.hProcess, t_send));
  kill_close(&pi);
  CloseHandle(in_w);
  if (hpc) closepc(hpc);
  WaitForSingleObject(reader, 2000);
  CloseHandle(reader); CloseHandle(out_r);
  DeleteProcThreadAttributeList(attrs);
}

static void probe_conpty(void) {
  run_conpty_case("conpty_write_ETX_to_input__handler_returns_true", L"handler_true", "ctrl_c", 0);
  run_conpty_case("conpty_write_ETX_to_input__no_handler", L"default", "ctrl_c", 1);
  run_conpty_case("conpty_write_ETX_to_input__ignored_by_child", L"ignore", "ctrl_c", 2);
  run_conpty_case("conpty_attach_and_CTRL_BREAK__handler_returns_true", L"handler_true", "attach_break", 3);
  run_conpty_case("conpty_close_pseudoconsole__handler_returns_true", L"handler_true", "close", 4);
  run_conpty_case("conpty_close_pseudoconsole__no_handler", L"default", "close", 5);
}

/* ------------------------------------------------------------------ parent process attribute */
static DWORD parent_pid_of(DWORD pid) {
  HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (s == INVALID_HANDLE_VALUE) return 0xFFFFFFFF;
  PROCESSENTRY32W e;
  e.dwSize = sizeof e;
  DWORD r = 0xFFFFFFFF;
  if (Process32FirstW(s, &e)) do { if (e.th32ProcessID == pid) { r = e.th32ParentProcessID; break; } } while (Process32NextW(s, &e));
  CloseHandle(s);
  return r;
}

static DWORD find_process(const wchar_t *name) {
  HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  PROCESSENTRY32W e;
  e.dwSize = sizeof e;
  DWORD r = 0;
  if (s != INVALID_HANDLE_VALUE && Process32FirstW(s, &e)) do { if (_wcsicmp(e.szExeFile, name) == 0) { r = e.th32ProcessID; break; } } while (Process32NextW(s, &e));
  if (s != INVALID_HANDLE_VALUE) CloseHandle(s);
  return r;
}

static void probe_parent(void) {
  HANDLE job = CreateJobObjectW(NULL, NULL);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION ex;
  memset(&ex, 0, sizeof ex);
  ex.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  SetInformationJobObject(job, JobObjectExtendedLimitInformation, &ex, sizeof ex);
  PROCESS_INFORMATION P, C;
  DWORD e;
  if (!spawn_self(L"--child-sleep 30000", IDLE_PRIORITY_CLASS, NULL, &P, &e)) { emit("parent_attribute", "\"error\":\"cannot start the stand-in parent: %lu\"", (unsigned long)e); return; }
  BOOL assigned = AssignProcessToJobObject(job, P.hProcess);
  DWORD assign_err = assigned ? 0 : GetLastError();
  LPPROC_THREAD_ATTRIBUTE_LIST attrs = make_attrs(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &P.hProcess, sizeof(HANDLE));
  BOOL ok = attrs && spawn_self(L"--child-sleep 30000", 0, attrs, &C, &e);
  if (!ok) { emit("parent_attribute", "\"create_with_parent_ok\":false,\"error\":%lu", (unsigned long)(attrs ? e : GetLastError())); kill_close(&P); CloseHandle(job); return; }
  BOOL in_job = FALSE, in_any = FALSE;
  IsProcessInJob(C.hProcess, job, &in_job);
  IsProcessInJob(C.hProcess, NULL, &in_any);
  DWORD cp = parent_pid_of(C.dwProcessId);
  DWORD cls_c = GetPriorityClass(C.hProcess), cls_p = GetPriorityClass(P.hProcess), cls_self = GetPriorityClass(GetCurrentProcess());
  emit("parent_attribute_child_of_stand_in",
       "\"job_assign_ok\":%s,\"job_assign_err\":%lu,\"reported_parent_is_stand_in\":%s,\"reported_parent_is_us\":%s,\"child_in_stand_in_job\":%s,\"child_in_any_job\":%s,"
       "\"priority_class_child\":\"0x%lX\",\"priority_class_stand_in\":\"0x%lX\",\"priority_class_us\":\"0x%lX\"",
       bstr(assigned), (unsigned long)assign_err, bstr(cp == P.dwProcessId), bstr(cp == GetCurrentProcessId()), bstr(in_job), bstr(in_any),
       (unsigned long)cls_c, (unsigned long)cls_p, (unsigned long)cls_self);
  TerminateProcess(P.hProcess, 1);
  WaitForSingleObject(P.hProcess, 2000);
  Sleep(300);
  DWORD cp2 = parent_pid_of(C.dwProcessId);
  int c_alive = WaitForSingleObject(C.hProcess, 0) == WAIT_TIMEOUT;
  BOOL in_job2 = FALSE;
  IsProcessInJob(C.hProcess, job, &in_job2);
  emit("parent_attribute_after_stand_in_exits", "\"reported_parent_unchanged\":%s,\"child_alive\":%s,\"child_still_in_job\":%s", bstr(cp2 == P.dwProcessId), bstr(c_alive), bstr(in_job2));
  kill_close(&C); kill_close(&P);
  DeleteProcThreadAttributeList(attrs);

  /* parent = a process we did not create */
  const wchar_t *targets[] = {L"explorer.exe", L"services.exe", L"winlogon.exe", L"svchost.exe"};
  DWORD our_parent = parent_pid_of(GetCurrentProcessId());
  DWORD our_session = 0xFFFFFFFF;
  ProcessIdToSessionId(GetCurrentProcessId(), &our_session);
  DWORD pids[5] = {our_parent, 0, 0, 0, 0};
  const wchar_t *names[5] = {L"our_parent", L"explorer.exe", L"services.exe", L"winlogon.exe", L"svchost.exe"};
  for (int i = 0; i < 4; i++) pids[i + 1] = find_process(targets[i]);
  for (int i = 0; i < 5; i++) {
    char nm[64];
    snprintf(nm, sizeof nm, "parent_attribute_foreign_%ls", names[i]);
    if (!pids[i]) { emit(nm, "\"present\":false"); continue; }
    HANDLE h = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pids[i]);
    DWORD oe = h ? 0 : GetLastError();
    int spawned = 0;
    DWORD se = 0;
    DWORD reported = 0, child_session = 0xFFFFFFFF, target_session = 0xFFFFFFFF;
    ProcessIdToSessionId(pids[i], &target_session);
    if (h) {
      LPPROC_THREAD_ATTRIBUTE_LIST a2 = make_attrs(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &h, sizeof(HANDLE));
      PROCESS_INFORMATION x;
      spawned = a2 && spawn_self(L"--child-sleep 2000", 0, a2, &x, &se);
      if (!a2) se = GetLastError();
      if (spawned) { reported = parent_pid_of(x.dwProcessId); ProcessIdToSessionId(x.dwProcessId, &child_session); kill_close(&x); }
      if (a2) DeleteProcThreadAttributeList(a2);
      CloseHandle(h);
    }
    emit(nm, "\"present\":true,\"OpenProcess_PROCESS_CREATE_PROCESS_ok\":%s,\"OpenProcess_err\":%lu,\"spawn_with_this_parent_ok\":%s,\"spawn_err\":%lu,\"child_reports_that_parent\":%s,"
         "\"target_pid\":%lu,\"child_reported_parent_pid\":%lu,\"target_session\":%ld,\"child_session\":%ld,\"our_session\":%ld",
         bstr(h != NULL), (unsigned long)oe, bstr(spawned), (unsigned long)se, bstr(spawned && reported == pids[i]),
         (unsigned long)pids[i], (unsigned long)reported, (long)target_session, (long)child_session, (long)our_session);
  }
  CloseHandle(job);
}

/* ------------------------------------------------------------------ waits */
static volatile LONG g_fired;
static VOID CALLBACK wait_cb(PVOID ctx, BOOLEAN timed_out) { (void)ctx; if (!timed_out) InterlockedIncrement(&g_fired); }

static void probe_wait(void) {
  HANDLE ev[70];
  for (int i = 0; i < 70; i++) ev[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
  DWORD r64 = WaitForMultipleObjects(64, ev, FALSE, 10);
  DWORD r65 = WaitForMultipleObjects(65, ev, FALSE, 10);
  DWORD r65e = r65 == WAIT_FAILED ? GetLastError() : 0;
  emit("wait_multiple_limits", "\"MAXIMUM_WAIT_OBJECTS\":%d,\"wait_64_handles_result\":%lu,\"wait_65_handles_result\":\"%s\",\"wait_65_error\":%lu",
       MAXIMUM_WAIT_OBJECTS, (unsigned long)r64, r65 == WAIT_FAILED ? "WAIT_FAILED" : "other", (unsigned long)r65e);
  SetEvent(ev[30]); SetEvent(ev[9]); SetEvent(ev[5]);
  DWORD first = WaitForMultipleObjects(64, ev, FALSE, 100);
  ResetEvent(ev[5]);
  DWORD second = WaitForMultipleObjects(64, ev, FALSE, 100);
  emit("wait_any_with_several_signaled", "\"signaled\":\"5,9,30\",\"first_returned_index\":%ld,\"after_reset_of_5_returned_index\":%ld",
       (long)(first - WAIT_OBJECT_0), (long)(second - WAIT_OBJECT_0));
  HANDLE all[4];
  for (int i = 0; i < 4; i++) all[i] = CreateEventW(NULL, FALSE, FALSE, NULL); /* auto-reset */
  SetEvent(all[0]); SetEvent(all[1]); SetEvent(all[2]);
  DWORD a1 = WaitForMultipleObjects(4, all, TRUE, 50);
  SetEvent(all[3]);
  DWORD a2 = WaitForMultipleObjects(4, all, TRUE, 500);
  DWORD a3 = WaitForMultipleObjects(4, all, TRUE, 50);
  emit("wait_all_semantics", "\"three_of_four_signaled\":\"%s\",\"after_fourth\":\"%s\",\"again_auto_reset_consumed\":\"%s\"",
       a1 == WAIT_TIMEOUT ? "timeout" : "other", a2 == WAIT_OBJECT_0 ? "satisfied" : "other", a3 == WAIT_TIMEOUT ? "timeout" : "other");

  /* eight processes finishing in reverse start order; wait-any repeatedly */
  HANDLE hs[8];
  int orig[8];
  PROCESS_INFORMATION pis[8];
  for (int i = 0; i < 8; i++) {
    wchar_t a[64];
    swprintf(a, 64, L"--child-sleep %d", (8 - i) * 150);
    DWORD se;
    spawn_self(a, 0, NULL, &pis[i], &se);
    hs[i] = pis[i].hProcess;
    orig[i] = i;
  }
  char seq[128] = "";
  size_t sl = 0;
  double max_lat = 0, prev_exit = 0;
  int in_exit_order = 1;
  int n = 8;
  while (n > 0) {
    DWORD w = WaitForMultipleObjects(n, hs, FALSE, 5000);
    double woke = abs_ms();
    if (w >= WAIT_OBJECT_0 + n) { sl += (size_t)snprintf(seq + sl, sizeof seq - sl, "timeout"); break; }
    int k = (int)(w - WAIT_OBJECT_0);
    FILETIME c, x, kt, ut;
    GetProcessTimes(hs[k], &c, &x, &kt, &ut);
    double lat = woke - ft_ms(x);
    if (ft_ms(x) < prev_exit) in_exit_order = 0;
    prev_exit = ft_ms(x);
    if (lat > max_lat) max_lat = lat;
    sl += (size_t)snprintf(seq + sl, sizeof seq - sl, "%s%d", sl ? "," : "", orig[k]);
    hs[k] = hs[n - 1]; orig[k] = orig[n - 1];
    n--;
  }
  emit("wait_any_over_eight_processes", "\"wake_order_by_start_index\":\"%s\",\"if_started_instantly\":\"7,6,5,4,3,2,1,0\",\"wakeups_in_kernel_exit_time_order\":%s,"
       "\"max_ms_between_process_exit_time_and_wakeup\":%.1f", seq, bstr(in_exit_order), max_lat);
  for (int i = 0; i < 8; i++) { CloseHandle(pis[i].hProcess); CloseHandle(pis[i].hThread); }

  /* registered waits at scale */
  int counts[2] = {200, 2000};
  for (int c = 0; c < 2; c++) {
    int N = counts[c];
    HANDLE *evs = (HANDLE *)calloc((size_t)N, sizeof(HANDLE));
    HANDLE *wh = (HANDLE *)calloc((size_t)N, sizeof(HANDLE));
    g_fired = 0;
    int reg_ok = 0;
    for (int i = 0; i < N; i++) {
      evs[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
      if (RegisterWaitForSingleObject(&wh[i], evs[i], wait_cb, NULL, INFINITE, WT_EXECUTEONLYONCE)) reg_ok++;
    }
    double t0 = abs_ms();
    for (int i = 0; i < N; i++) SetEvent(evs[i]);
    while (g_fired < N && abs_ms() - t0 < 10000) Sleep(5);
    double dt = abs_ms() - t0;
    emit("registered_waits_signaled_together", "\"waits\":%d,\"registered_ok\":%d,\"callbacks_fired\":%ld,\"ms\":%.0f", N, reg_ok, (long)g_fired, dt);
    for (int i = 0; i < N; i++) { if (wh[i]) UnregisterWaitEx(wh[i], INVALID_HANDLE_VALUE); CloseHandle(evs[i]); }
    free(evs); free(wh);
  }

  /* is a job handle ever signaled? time limit with POST vs TERMINATE at end of job */
  HANDLE jobs[2];
  PROCESS_INFORMATION jp[2];
  HANDLE port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
  for (int i = 0; i < 2; i++) {
    jobs[i] = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_BASIC_LIMIT_INFORMATION bl;
    memset(&bl, 0, sizeof bl);
    bl.LimitFlags = JOB_OBJECT_LIMIT_JOB_TIME;
    bl.PerJobUserTimeLimit.QuadPart = 10000; /* 1 ms */
    BOOL s1 = SetInformationJobObject(jobs[i], JobObjectBasicLimitInformation, &bl, sizeof bl);
    JOBOBJECT_END_OF_JOB_TIME_INFORMATION eoj;
    eoj.EndOfJobTimeAction = i == 0 ? JOB_OBJECT_POST_AT_END_OF_JOB : JOB_OBJECT_TERMINATE_AT_END_OF_JOB;
    BOOL s2 = SetInformationJobObject(jobs[i], JobObjectEndOfJobTimeInformation, &eoj, sizeof eoj);
    if (i == 0) {
      JOBOBJECT_ASSOCIATE_COMPLETION_PORT acp;
      acp.CompletionKey = (PVOID)(ULONG_PTR)0x77;
      acp.CompletionPort = port;
      SetInformationJobObject(jobs[i], JobObjectAssociateCompletionPortInformation, &acp, sizeof acp);
    }
    DWORD se;
    spawn_self(L"--child-spin", CREATE_SUSPENDED, NULL, &jp[i], &se);
    BOOL as = AssignProcessToJobObject(jobs[i], jp[i].hProcess);
    ResumeThread(jp[i].hThread);
    if (!s1 || !s2 || !as) emit("job_handle_signal_setup", "\"job\":%d,\"limit_ok\":%s,\"end_action_ok\":%s,\"assign_ok\":%s,\"err\":%lu", i, bstr(s1), bstr(s2), bstr(as), (unsigned long)GetLastError());
  }
  double t0 = abs_ms();
  double sig[2] = {-1, -1};
  for (int round = 0; round < 2; round++) {
    HANDLE pending[2];
    int map[2], np = 0;
    for (int i = 0; i < 2; i++) if (sig[i] < 0) { pending[np] = jobs[i]; map[np++] = i; }
    if (!np) break;
    DWORD w = WaitForMultipleObjects((DWORD)np, pending, FALSE, round == 0 ? 20000 : 3000);
    if (w < WAIT_OBJECT_0 + (DWORD)np) sig[map[w - WAIT_OBJECT_0]] = abs_ms() - t0;
    else break;
  }
  int alive0 = WaitForSingleObject(jp[0].hProcess, 0) == WAIT_TIMEOUT, alive1 = WaitForSingleObject(jp[1].hProcess, 0) == WAIT_TIMEOUT;
  char msgs[256] = "";
  size_t ml = 0;
  DWORD msg;
  ULONG_PTR key;
  LPOVERLAPPED ov;
  while (GetQueuedCompletionStatus(port, &msg, &key, &ov, 0)) ml += (size_t)snprintf(msgs + ml, sizeof msgs - ml, "%s%lu", ml ? "," : "", (unsigned long)msg);
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acct;
  memset(&acct, 0, sizeof acct);
  QueryInformationJobObject(jobs[0], JobObjectBasicAccountingInformation, &acct, sizeof acct, NULL);
  emit("job_handle_signaled_at_time_limit",
       "\"post_at_end_of_job_signaled_ms\":%.0f,\"post_at_end_of_job_child_alive\":%s,\"post_job_port_messages\":\"%s\",\"post_job_user_ms\":%.0f,"
       "\"terminate_at_end_of_job_signaled_ms\":%.0f,\"terminate_at_end_of_job_child_alive\":%s,"
       "\"note\":\"-1 = never signaled within the wait; port messages: 1 END_OF_JOB_TIME, 2 END_OF_PROCESS_TIME, 4 ACTIVE_PROCESS_ZERO, 6 NEW_PROCESS, 7 EXIT_PROCESS\"",
       sig[0], bstr(alive0), msgs, (double)acct.TotalUserTime.QuadPart / 10000.0, sig[1], bstr(alive1));
  for (int i = 0; i < 2; i++) { kill_close(&jp[i]); CloseHandle(jobs[i]); }
  CloseHandle(port);
  for (int i = 0; i < 70; i++) CloseHandle(ev[i]);
  for (int i = 0; i < 4; i++) CloseHandle(all[i]);
}

/* ------------------------------------------------------------------ job rate control */
typedef struct { ULONG64 MaxBandwidth; DWORD ControlFlags; BYTE DscpTag; } MY_NET_RATE;
typedef struct { LONG64 MaxIops; LONG64 MaxBandwidth; LONG64 ReservationIops; PCWSTR VolumeName; ULONG BaseIoSize; ULONG ControlFlags; } MY_IO_RATE;
typedef DWORD(WINAPI *PFN_SetIoRate)(HANDLE, MY_IO_RATE *);
typedef DWORD(WINAPI *PFN_QueryIoRate)(HANDLE, PCWSTR, MY_IO_RATE **, ULONG *);

static void probe_rate(void) {
  HANDLE job = CreateJobObjectW(NULL, NULL);
  struct { const char *name; DWORD flags; ULONG64 bw; BYTE dscp; } nets[] = {
    {"net_rate_enable_max_bandwidth_1MB", 1 | 2, 1000000, 0},
    {"net_rate_enable_dscp_tag_8", 1 | 4, 0, 8},
    {"net_rate_disable", 0, 0, 0},
  };
  for (int i = 0; i < 3; i++) {
    MY_NET_RATE n;
    memset(&n, 0, sizeof n);
    n.MaxBandwidth = nets[i].bw; n.ControlFlags = nets[i].flags; n.DscpTag = nets[i].dscp;
    BOOL s = SetInformationJobObject(job, (JOBOBJECTINFOCLASS)32 /* JobObjectNetRateControlInformation */, &n, sizeof n);
    DWORD se = s ? 0 : GetLastError();
    MY_NET_RATE q;
    memset(&q, 0xAA, sizeof q);
    DWORD ret = 0;
    BOOL qs = QueryInformationJobObject(job, (JOBOBJECTINFOCLASS)32, &q, sizeof q, &ret);
    DWORD qe = qs ? 0 : GetLastError();
    emit(nets[i].name, "\"struct_size\":%u,\"set_ok\":%s,\"set_err\":%lu,\"query_ok\":%s,\"query_err\":%lu,\"query_flags\":%lu,\"query_max_bandwidth\":%llu,\"query_dscp\":%u",
         (unsigned)sizeof n, bstr(s), (unsigned long)se, bstr(qs), (unsigned long)qe, (unsigned long)(qs ? q.ControlFlags : 0),
         (unsigned long long)(qs ? q.MaxBandwidth : 0), (unsigned)(qs ? q.DscpTag : 0));
  }
  HMODULE k = GetModuleHandleW(L"kernel32.dll");
  PFN_SetIoRate setio = (PFN_SetIoRate)(void *)GetProcAddress(k, "SetIoRateControlInformationJobObject");
  PFN_QueryIoRate queryio = (PFN_QueryIoRate)(void *)GetProcAddress(k, "QueryIoRateControlInformationJobObject");
  if (!setio) { emit("io_rate_control", "\"unsupported\":\"SetIoRateControlInformationJobObject is not exported by kernel32\""); }
  else {
    ULONG flag_sets[2] = {1, 1 | 2};
    for (int i = 0; i < 2; i++) {
      MY_IO_RATE r;
      memset(&r, 0, sizeof r);
      r.MaxIops = 100; r.MaxBandwidth = 1000000; r.BaseIoSize = 1; r.ControlFlags = flag_sets[i];
      SetLastError(0);
      DWORD ret = setio(job, &r);
      DWORD le = GetLastError();
      MY_IO_RATE *blocks = NULL;
      ULONG count = 0;
      SetLastError(0);
      DWORD qr = queryio ? queryio(job, NULL, &blocks, &count) : 0xFFFFFFFF;
      DWORD qe = GetLastError();
      if (blocks) {
        typedef VOID(WINAPI * PFN_FreeMemoryJobObject)(VOID *);
        PFN_FreeMemoryJobObject fm = (PFN_FreeMemoryJobObject)(void *)GetProcAddress(k, "FreeMemoryJobObject");
        if (fm) fm(blocks);
      }
      emit(i == 0 ? "io_rate_control_enable" : "io_rate_control_enable_standalone_volume",
           "\"set_return\":%lu,\"last_error\":%lu,\"query_return\":%lu,\"query_last_error\":%lu,\"query_block_count\":%lu,\"first_block_max_iops\":%lld",
           (unsigned long)ret, (unsigned long)le, (unsigned long)qr, (unsigned long)qe, (unsigned long)count, (long long)(blocks && count ? blocks[0].MaxIops : -1));
    }
  }
  CloseHandle(job);

}

/* ------------------------------------------------------------------ I/O rate control, in detail */
/* With MaxIops = 20 a child doing 4 KiB write-through appends managed 9-10 writes/s (run 41788061976). Which I/Os
 * count? Each variant runs a child for a fixed window inside a job with a limit, and once without, and reports the
 * job's I/O counters. Appending writes also extend the file (metadata), so overwrite-in-place variants use a file
 * the parent created and filled beforehand. */
static int child_io(const wchar_t *mode, const wchar_t *path, int size, int flags) {
  DWORD fl = ((flags & 1) ? FILE_FLAG_NO_BUFFERING : 0) | ((flags & 2) ? FILE_FLAG_WRITE_THROUGH : 0);
  int reading = mode[0] == L'r', appending = mode[0] == L'a';
  HANDLE h = CreateFileW(path, reading ? GENERIC_READ : GENERIC_WRITE, FILE_SHARE_READ, NULL, appending ? CREATE_ALWAYS : OPEN_EXISTING,
                         fl ? fl : FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) return 2;
  void *buf = VirtualAlloc(NULL, (SIZE_T)size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!buf) return 4;
  memset(buf, 'w', (size_t)size);
  LARGE_INTEGER fsz;
  GetFileSizeEx(h, &fsz);
  LONGLONG pos = 0;
  for (;;) {
    DWORD n;
    if (!appending) {
      if (pos + size > fsz.QuadPart) pos = 0;
      LARGE_INTEGER li;
      li.QuadPart = pos;
      SetFilePointerEx(h, li, NULL, FILE_BEGIN);
      pos += size;
    }
    BOOL ok = reading ? ReadFile(h, buf, (DWORD)size, &n, NULL) : WriteFile(h, buf, (DWORD)size, &n, NULL);
    if (!ok) return (int)(0x10000u | GetLastError()); /* exit code says which error */
    if (mode[0] == L'f') FlushFileBuffers(h); /* buffered overwrite + flush after each write */
  }
}

typedef struct { const char *name; const wchar_t *mode; int size, flags; LONG64 max_iops, max_bw; ULONG base; } io_case_t;

/* overwrite in place and keep going after failures; one log line per elapsed second */
static int child_io_log(const wchar_t *path, int size, const wchar_t *logpath) {
  HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);
  if (h == INVALID_HANDLE_VALUE) return 2;
  HANDLE log = open_log(logpath);
  void *buf = VirtualAlloc(NULL, (SIZE_T)size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  memset(buf, 'w', (size_t)size);
  LARGE_INTEGER fsz;
  GetFileSizeEx(h, &fsz);
  LONGLONG pos = 0;
  double t0 = abs_ms(), next = t0 + 1000, first_fail = -1;
  unsigned long ok = 0, fail = 0, last_err = 0;
  for (;;) {
    if (pos + size > fsz.QuadPart) pos = 0;
    LARGE_INTEGER li;
    li.QuadPart = pos;
    SetFilePointerEx(h, li, NULL, FILE_BEGIN);
    pos += size;
    DWORD n;
    if (WriteFile(h, buf, (DWORD)size, &n, NULL)) ok++;
    else { fail++; last_err = GetLastError(); if (first_fail < 0) first_fail = abs_ms() - t0; }
    double now = abs_ms();
    if (now >= next) {
      log_to(log, "t=%.0f ok=%lu fail=%lu last_err=%lu first_fail=%.0f\n", now - t0, ok, fail, last_err, first_fail);
      next += 1000;
    }
  }
}

static void prefill(const wchar_t *path, LONGLONG bytes) {
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) return;
  char *b = (char *)malloc(1 << 20);
  memset(b, 'p', 1 << 20);
  for (LONGLONG done = 0; done < bytes; done += 1 << 20) { DWORD w; WriteFile(h, b, 1 << 20, &w, NULL); }
  FlushFileBuffers(h);
  CloseHandle(h);
  free(b);
}

static void io_run(const io_case_t *c, int limited, PFN_SetIoRate setio, const wchar_t *path, DWORD window_ms, char *out, size_t cap) {
  HANDLE j = CreateJobObjectW(NULL, NULL);
  DWORD sret = 0, serr = 0;
  if (limited) {
    MY_IO_RATE r;
    memset(&r, 0, sizeof r);
    r.MaxIops = c->max_iops;
    r.MaxBandwidth = c->max_bw;
    r.BaseIoSize = c->base; /* documented as "must be 0" for Set, but a nonzero value was accepted */
    r.ControlFlags = 1;
    SetLastError(0);
    sret = setio(j, &r);
    serr = GetLastError();
  }
  wchar_t args[1024];
  swprintf(args, 1024, L"--child-io %ls \"%ls\" %d %d", c->mode, path, c->size, c->flags);
  PROCESS_INFORMATION pi;
  DWORD e = 0;
  if (!spawn_self(args, CREATE_SUSPENDED, NULL, &pi, &e)) { snprintf(out, cap, "\"spawn_error\":%lu", (unsigned long)e); CloseHandle(j); return; }
  AssignProcessToJobObject(j, pi.hProcess);
  ResumeThread(pi.hThread);
  Sleep(window_ms);
  int ex = WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0;
  DWORD code = 0;
  GetExitCodeProcess(pi.hProcess, &code);
  JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION io;
  memset(&io, 0, sizeof io);
  QueryInformationJobObject(j, JobObjectBasicAndIoAccountingInformation, &io, sizeof io, NULL);
  double s = window_ms / 1000.0;
  snprintf(out, cap, "\"set_return\":%lu,\"set_err\":%lu,\"child_ended_early\":%s,\"child_exit\":\"0x%08lX\",\"reads_per_s\":%.1f,\"writes_per_s\":%.1f,\"other_per_s\":%.1f,\"kib_per_s\":%.0f",
           (unsigned long)sret, (unsigned long)serr, bstr(ex), (unsigned long)code, io.IoInfo.ReadOperationCount / s, io.IoInfo.WriteOperationCount / s,
           io.IoInfo.OtherOperationCount / s, (double)(io.IoInfo.ReadTransferCount + io.IoInfo.WriteTransferCount) / 1024.0 / s);
  kill_close(&pi);
  CloseHandle(j);
}

static void probe_iorate(void) {
  HMODULE k = GetModuleHandleW(L"kernel32.dll");
  PFN_SetIoRate setio = (PFN_SetIoRate)(void *)GetProcAddress(k, "SetIoRateControlInformationJobObject");
  PFN_QueryIoRate queryio = (PFN_QueryIoRate)(void *)GetProcAddress(k, "QueryIoRateControlInformationJobObject");
  if (!setio || !queryio) { emit("iorate", "\"unsupported\":\"not exported\""); return; }

  /* return convention: what does Set return for a handle that is not a job? */
  {
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    MY_IO_RATE r;
    memset(&r, 0, sizeof r);
    r.MaxIops = 20; r.ControlFlags = 1;
    SetLastError(0);
    DWORD bad = setio(ev, &r);
    DWORD bad_err = GetLastError();
    HANDLE j = CreateJobObjectW(NULL, NULL);
    SetLastError(0);
    DWORD good = setio(j, &r);
    DWORD good_err = GetLastError();
    r.BaseIoSize = 4096;
    SetLastError(0);
    DWORD nonzero_base = setio(j, &r);
    DWORD nonzero_base_err = GetLastError();
    emit("iorate_return_convention", "\"event_handle_return\":%lu,\"event_handle_err\":%lu,\"job_return\":%lu,\"job_err\":%lu,\"job_base_io_size_4096_return\":%lu,\"job_base_io_size_4096_err\":%lu",
         (unsigned long)bad, (unsigned long)bad_err, (unsigned long)good, (unsigned long)good_err, (unsigned long)nonzero_base, (unsigned long)nonzero_base_err);
    /* query with the C: volume's NT device name */
    wchar_t dev[512] = L"";
    QueryDosDeviceW(L"C:", dev, 512);
    MY_IO_RATE *blocks = NULL;
    ULONG count = 0;
    SetLastError(0);
    DWORD q1 = queryio(j, NULL, &blocks, &count);
    DWORD q1e = GetLastError();
    ULONG c1 = count;
    LONG64 iops1 = blocks && count ? blocks[0].MaxIops : -1;
    ULONG base1 = blocks && count ? blocks[0].BaseIoSize : 0;
    blocks = NULL; count = 0;
    SetLastError(0);
    DWORD q2 = queryio(j, dev, &blocks, &count);
    DWORD q2e = GetLastError();
    char devn[512];
    WideCharToMultiByte(CP_UTF8, 0, dev, -1, devn, sizeof devn, NULL, NULL);
    for (char *p = devn; *p; p++) if (*p == '\\') *p = '/';
    emit("iorate_query", "\"c_volume_device\":\"%s\",\"query_all_return\":%lu,\"query_all_err\":%lu,\"query_all_blocks\":%lu,\"query_all_max_iops\":%lld,\"query_all_base_io_size\":%lu,"
         "\"query_c_return\":%lu,\"query_c_err\":%lu,\"query_c_blocks\":%lu,\"query_c_max_iops\":%lld,\"query_c_base_io_size\":%lu",
         devn, (unsigned long)q1, (unsigned long)q1e, (unsigned long)c1, (long long)iops1, (unsigned long)base1,
         (unsigned long)q2, (unsigned long)q2e, (unsigned long)count, (long long)(blocks && count ? blocks[0].MaxIops : -1), (unsigned long)(blocks && count ? blocks[0].BaseIoSize : 0));
    CloseHandle(j);
    CloseHandle(ev);
  }
  {
    HKEY key;
    DWORD v = 0, sz = sizeof v, type = 0;
    LONG rr = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\QoS", 0, KEY_READ, &key);
    LONG rv = -1;
    if (rr == ERROR_SUCCESS) { rv = RegQueryValueExW(key, L"StorageBaseIOSize", NULL, &type, (LPBYTE)&v, &sz); RegCloseKey(key); }
    emit("iorate_registry", "\"qos_key_open\":%ld,\"StorageBaseIOSize_query\":%ld,\"StorageBaseIOSize\":%lu", (long)rr, (long)rv, (unsigned long)(rv == 0 ? v : 0));
  }

  wchar_t fpre[MAX_PATH * 2], fapp[MAX_PATH * 2];
  tmp_file(fpre, MAX_PATH * 2, L"io-prefilled.bin");
  tmp_file(fapp, MAX_PATH * 2, L"io-append.bin");
  prefill(fpre, 8LL << 20);
  static const io_case_t cases[] = {
    {"iorate_4k_append_writethrough_unbuffered", L"a", 4096, 3, 20, 0, 0},
    {"iorate_4k_overwrite_writethrough_unbuffered", L"o", 4096, 3, 20, 0, 0},
    {"iorate_4k_overwrite_unbuffered", L"o", 4096, 1, 20, 0, 0},
    {"iorate_4k_append_unbuffered", L"a", 4096, 1, 20, 0, 0},
    {"iorate_4k_overwrite_buffered_flush_each", L"f", 4096, 0, 20, 0, 0},
    {"iorate_4k_read_unbuffered", L"r", 4096, 1, 20, 0, 0},
    {"iorate_64k_overwrite_unbuffered", L"o", 65536, 1, 20, 0, 0},
    {"iorate_4k_overwrite_unbuffered_limit_40", L"o", 4096, 1, 40, 0, 0},
    {"iorate_64k_overwrite_unbuffered_bandwidth_1MB", L"o", 65536, 1, 0, 1000000, 0},
    {"iorate_4k_overwrite_unbuffered_bandwidth_1MB", L"o", 4096, 1, 0, 1000000, 0},
    {"iorate_64k_overwrite_unbuffered_bandwidth_10MB", L"o", 65536, 1, 0, 10000000, 0},
    {"iorate_64k_overwrite_unbuffered_iops_20_base_io_size_4096", L"o", 65536, 1, 20, 0, 4096},
    {"iorate_64k_overwrite_unbuffered_iops_20_base_io_size_65536", L"o", 65536, 1, 20, 0, 65536},
  };
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
    const io_case_t *c = &cases[i];
    const wchar_t *path = c->mode[0] == L'a' ? fapp : fpre;
    char lim[512], free_[512];
    io_run(c, 1, setio, path, 5000, lim, sizeof lim);
    io_run(c, 0, setio, path, 1500, free_, sizeof free_);
    emit(c->name, "\"max_iops\":%lld,\"max_bandwidth\":%lld,\"base_io_size\":%lu,\"io_size\":%d,\"limited\":{%s},\"unlimited\":{%s}", (long long)c->max_iops, (long long)c->max_bw,
         (unsigned long)c->base, c->size, lim, free_);
  }

  /* bandwidth limits: does the write after the first second's budget fail once, or keep failing? */
  struct { const char *name; int size; LONG64 iops, bw; } bws[] = {
    {"iorate_bandwidth_1MB_64k_timeline", 65536, 0, 1000000},
    {"iorate_bandwidth_1MB_with_iops_1000_64k_timeline", 65536, 1000, 1000000},
    {"iorate_bandwidth_10MB_64k_timeline", 65536, 0, 10000000},
    {"iorate_bandwidth_1MB_4k_timeline", 4096, 0, 1000000},
  };
  for (size_t i = 0; i < sizeof bws / sizeof bws[0]; i++) {
    HANDLE j = CreateJobObjectW(NULL, NULL);
    MY_IO_RATE r;
    memset(&r, 0, sizeof r);
    r.MaxIops = bws[i].iops;
    r.MaxBandwidth = bws[i].bw;
    r.ControlFlags = 1;
    DWORD sret = setio(j, &r);
    wchar_t lg[MAX_PATH * 2], ln[64], args[1024];
    swprintf(ln, 64, L"iobw-%d.log", (int)i);
    tmp_file(lg, MAX_PATH * 2, ln);
    DeleteFileW(lg);
    swprintf(args, 1024, L"--child-io-log \"%ls\" %d \"%ls\"", fpre, bws[i].size, lg);
    PROCESS_INFORMATION pi;
    DWORD e = 0;
    if (!spawn_self(args, CREATE_SUSPENDED, NULL, &pi, &e)) { emit(bws[i].name, "\"spawn_error\":%lu", (unsigned long)e); CloseHandle(j); continue; }
    AssignProcessToJobObject(j, pi.hProcess);
    ResumeThread(pi.hThread);
    Sleep(6500);
    int ended = WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0;
    char b[2048] = "";
    read_text(lg, b, sizeof b);
    for (char *q = b; *q; q++) if (*q == '\n') *q = '|'; else if (*q == '\r') *q = ' ';
    emit(bws[i].name, "\"max_iops\":%lld,\"max_bandwidth\":%lld,\"io_size\":%d,\"set_return\":%lu,\"child_ended\":%s,\"per_second_cumulative\":\"%s\"",
         (long long)bws[i].iops, (long long)bws[i].bw, bws[i].size, (unsigned long)sret, bstr(ended), b);
    kill_close(&pi);
    CloseHandle(j);
  }
  DeleteFileW(fpre);
  DeleteFileW(fapp);
}

/* ------------------------------------------------------------------ child-process policy */
static void probe_mitigation(void) {
  struct { const char *name; DWORD policy; } cases[] = {
    {"child_process_policy_none", 0},
    {"child_process_policy_restricted", 0x1},
    {"child_process_policy_restricted_with_override", 0x1 | 0x2},
    {"child_process_policy_restricted_unless_secure", 0x4},
  };
  for (int i = 0; i < 4; i++) {
    wchar_t res[MAX_PATH * 2], rn[64], args[1024];
    swprintf(rn, 64, L"mitig-%d.res", i);
    tmp_file(res, MAX_PATH * 2, rn);
    DeleteFileW(res);
    swprintf(args, 1024, L"--child-spawn-try \"%ls\"", res);
    DWORD policy = cases[i].policy;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = make_attrs(PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &policy, sizeof policy);
    PROCESS_INFORMATION pi;
    DWORD err = 0;
    BOOL ok = attrs && spawn_self(args, 0, attrs, &pi, &err);
    if (!ok) { emit(cases[i].name, "\"attribute_or_spawn_error\":%lu,\"attrs_ok\":%s", (unsigned long)(attrs ? err : GetLastError()), bstr(attrs != NULL)); continue; }
    int exited;
    DWORD code = wait_exit(pi.hProcess, 8000, &exited);
    char b[256];
    read_text(res, b, sizeof b);
    b[strcspn(b, "\r\n")] = 0;
    emit(cases[i].name, "\"policy\":%lu,\"child_reported\":\"%s\",\"child_exit_code\":\"0x%08lX\"", (unsigned long)policy, b, (unsigned long)code);
    kill_close(&pi);
    DeleteProcThreadAttributeList(attrs);
  }
}

/* ------------------------------------------------------------------ crash timing and the debugger */
static void crash_case(const char *name, int nogpf) {
  wchar_t a[64];
  swprintf(a, 64, L"--child-crash %d", nogpf);
  PROCESS_INFORMATION pi;
  DWORD err;
  if (!spawn_self(a, 0, NULL, &pi, &err)) { emit(name, "\"spawn_error\":%lu", (unsigned long)err); return; }
  double t0 = abs_ms();
  double wer_seen = -1;
  int exited = 0;
  DWORD code = 0;
  while (abs_ms() - t0 < 30000) {
    if (WaitForSingleObject(pi.hProcess, 50) == WAIT_OBJECT_0) { exited = 1; break; }
    if (wer_seen < 0 && find_process(L"WerFault.exe")) wer_seen = abs_ms() - t0;
  }
  GetExitCodeProcess(pi.hProcess, &code);
  double dt = abs_ms() - t0;
  int wer_after = find_process(L"WerFault.exe") != 0;
  emit(name, "\"error_mode_suppresses_gp_fault_box\":%s,\"exited\":%s,\"ms_to_exit\":%.0f,\"exit_code\":\"0x%08lX\",\"WerFault_seen_while_running_ms\":%.0f,\"WerFault_present_after\":%s",
       bstr(nogpf), bstr(exited), dt, (unsigned long)code, wer_seen, bstr(wer_after));
  kill_close(&pi);
}

static void debug_crash_case(void) {
  PROCESS_INFORMATION pi;
  DWORD err;
  if (!spawn_self(L"--child-crash 0", DEBUG_ONLY_THIS_PROCESS, NULL, &pi, &err)) { emit("debugger_sees_child_crash", "\"spawn_error\":%lu", (unsigned long)err); return; }
  DEBUG_EVENT de;
  int counts[12] = {0};
  char exc[512] = "";
  size_t el = 0;
  DWORD exit_code = 0;
  int got_exit = 0;
  double t0 = abs_ms(), t_exc = -1, t_exit = -1;
  while (abs_ms() - t0 < 30000 && WaitForDebugEvent(&de, 5000)) {
    DWORD cont = DBG_CONTINUE;
    if (de.dwDebugEventCode < 12) counts[de.dwDebugEventCode]++;
    if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
      DWORD c = de.u.Exception.ExceptionRecord.ExceptionCode;
      if (c != 0x80000003 && t_exc < 0) t_exc = abs_ms() - t0;
      el += (size_t)snprintf(exc + el, sizeof exc - el, "%s%08lX/%s", el ? "," : "", (unsigned long)c, de.u.Exception.dwFirstChance ? "first" : "second");
      if (c != 0x80000003) cont = DBG_EXCEPTION_NOT_HANDLED;
    } else if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && de.u.CreateProcessInfo.hFile) {
      CloseHandle(de.u.CreateProcessInfo.hFile);
    } else if (de.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && de.u.LoadDll.hFile) {
      CloseHandle(de.u.LoadDll.hFile);
    } else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
      exit_code = de.u.ExitProcess.dwExitCode;
      got_exit = 1;
      t_exit = abs_ms() - t0;
    }
    ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont);
    if (got_exit) break;
  }
  emit("debugger_sees_child_crash",
       "\"exception_events\":\"%s\",\"create_process_events\":%d,\"create_thread_events\":%d,\"load_dll_events\":%d,\"exit_process_event\":%s,\"exit_code\":\"0x%08lX\","
       "\"ms_to_first_non_breakpoint_exception\":%.0f,\"ms_to_exit_event\":%.0f",
       exc, counts[CREATE_PROCESS_DEBUG_EVENT], counts[CREATE_THREAD_DEBUG_EVENT], counts[LOAD_DLL_DEBUG_EVENT], bstr(got_exit), (unsigned long)exit_code, t_exc, t_exit);
  kill_close(&pi);
}

static void debugger_dies_case(const char *name, int kill_on_exit) {
  wchar_t log[MAX_PATH * 2], args[1024];
  tmp_file(log, MAX_PATH * 2, kill_on_exit ? L"dbg-kill.log" : L"dbg-keep.log");
  DeleteFileW(log);
  swprintf(args, 1024, L"--child-debugger \"%ls\" %d", log, kill_on_exit);
  PROCESS_INFORMATION helper;
  DWORD err;
  if (!spawn_self(args, 0, NULL, &helper, &err)) { emit(name, "\"spawn_error\":%lu", (unsigned long)err); return; }
  int ready = wait_ready(log, helper.hProcess, 6000);
  char b[512] = "";
  read_text(log, b, sizeof b);
  unsigned long child_pid = 0;
  char *p = strstr(b, "child=");
  if (p) child_pid = strtoul(p + 6, NULL, 10);
  if (!ready || !child_pid) { emit(name, "\"error\":\"debugger helper not ready\",\"log\":\"%.60s\"", b); kill_close(&helper); return; }
  HANDLE ch = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, (DWORD)child_pid);
  int alive_before = ch && WaitForSingleObject(ch, 0) == WAIT_TIMEOUT;
  double t0 = abs_ms();
  TerminateProcess(helper.hProcess, 1);
  WaitForSingleObject(helper.hProcess, 2000);
  int died = ch && WaitForSingleObject(ch, 2500) == WAIT_OBJECT_0;
  double dt = abs_ms() - t0;
  DWORD code = 0;
  if (ch) GetExitCodeProcess(ch, &code);
  char *rl = strstr(b, "early_call_ok");
  char helper_said[160] = "";
  if (rl) { snprintf(helper_said, sizeof helper_said, "%s", rl); helper_said[strcspn(helper_said, "\r\n")] = 0; }
  emit(name, "\"kill_on_exit_mode\":%d,\"helper\":\"%s\",\"debuggee_alive_before\":%s,\"debuggee_died_after_debugger_was_terminated\":%s,\"ms\":%.0f,\"debuggee_exit_code\":\"0x%08lX\"",
       kill_on_exit, helper_said, bstr(alive_before), bstr(died), died ? dt : -1.0, (unsigned long)(died ? code : 0));
  if (ch) { TerminateProcess(ch, 1); CloseHandle(ch); }
  kill_close(&helper);
}

static void probe_debug(void) {
  crash_case("crash_without_debugger_default_error_mode", 0);
  crash_case("crash_without_debugger_SEM_NOGPFAULTERRORBOX", 1);
  debug_crash_case();
  debugger_dies_case("debuggee_when_its_debugger_is_terminated_default", 1);
  debugger_dies_case("debuggee_when_its_debugger_is_terminated_kill_on_exit_false", 0);
  debugger_dies_case("debuggee_when_its_debugger_is_terminated_kill_on_exit_false_called_too_early", 2);
}

/* ------------------------------------------------------------------ silo */
static void probe_silo(void) {
  HMODULE nt = GetModuleHandleW(L"ntdll.dll");
  typedef LONG(NTAPI * PFN_NtSetInformationJobObject)(HANDLE, int, PVOID, ULONG);
  PFN_NtSetInformationJobObject f = (PFN_NtSetInformationJobObject)(void *)GetProcAddress(nt, "NtSetInformationJobObject");
  if (!f) { emit("silo_create", "\"unsupported\":\"NtSetInformationJobObject not found\""); return; }
  for (int variant = 0; variant < 3; variant++) {
    HANDLE job = CreateJobObjectW(NULL, NULL);
    BOOL ready = TRUE;
    DWORD ready_err = 0;
    if (variant >= 1) {
      JOBOBJECT_EXTENDED_LIMIT_INFORMATION ex;
      memset(&ex, 0, sizeof ex);
      ex.BasicLimitInformation.LimitFlags = 0x00400000; /* JOB_OBJECT_LIMIT_SILO_READY */
      ready = SetInformationJobObject(job, JobObjectExtendedLimitInformation, &ex, sizeof ex);
      ready_err = ready ? 0 : GetLastError();
    }
    char dummy[8] = {0};
    LONG st = variant == 2 ? f(job, 35, dummy, 0) : f(job, 35 /* JobObjectCreateSilo */, NULL, 0);
    emit(variant == 0 ? "silo_create_plain_job" : variant == 1 ? "silo_create_after_LIMIT_SILO_READY" : "silo_create_after_LIMIT_SILO_READY_nonnull_buffer",
         "\"silo_ready_set_ok\":%s,\"silo_ready_err\":%lu,\"ntstatus\":\"0x%08lX\",\"note\":\"0 = created; 0xC0000022 access denied; 0xC0000003 class not valid; 0xC000000D invalid parameter\"",
         bstr(ready), (unsigned long)ready_err, (unsigned long)st);
    CloseHandle(job);
  }
}

/* ------------------------------------------------------------------ job CPU-time enforcement period */
/* On windows-2025, job and notification limits were enforced by a system-wide pass every 7.000 s
 * (explore/FINDINGS.md). This repeats that measurement without Crystal so other Windows builds and
 * arm64 can be compared, and adds the per-process limit, which job_explore measured only indirectly. */
static int start_limited_spinner(int per_process, HANDLE *job, PROCESS_INFORMATION *pi, DWORD *err) {
  *job = CreateJobObjectW(NULL, NULL);
  JOBOBJECT_BASIC_LIMIT_INFORMATION bl;
  memset(&bl, 0, sizeof bl);
  if (per_process) { bl.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_TIME; bl.PerProcessUserTimeLimit.QuadPart = 100 * 10000LL; }
  else { bl.LimitFlags = JOB_OBJECT_LIMIT_JOB_TIME; bl.PerJobUserTimeLimit.QuadPart = 100 * 10000LL; }
  if (!SetInformationJobObject(*job, JobObjectBasicLimitInformation, &bl, sizeof bl)) { *err = GetLastError(); return 0; }
  if (!spawn_self(L"--child-spin", CREATE_SUSPENDED, NULL, pi, err)) return 0;
  if (!AssignProcessToJobObject(*job, pi->hProcess)) { *err = GetLastError(); kill_close(pi); return 0; }
  ResumeThread(pi->hThread);
  return 1;
}

static void probe_period(void) {
  SYSTEM_INFO si;
  GetNativeSystemInfo(&si);
  DWORD adj = 0, inc = 0;
  BOOL dis = FALSE;
  GetSystemTimeAdjustment(&adj, &inc, &dis);
  LARGE_INTEGER qf;
  QueryPerformanceFrequency(&qf);
  emit("period_environment", "\"logical_processors\":%lu,\"clock_increment_100ns\":%lu,\"time_adjustment_100ns\":%lu,\"time_adjustment_disabled\":%s,\"qpc_frequency\":%lld",
       (unsigned long)si.dwNumberOfProcessors, (unsigned long)inc, (unsigned long)adj, bstr(dis), (long long)qf.QuadPart);
  double t_prog = abs_ms(), q_prog = qpc_ms(), i_prog = itime_ms();
  for (int kind = 0; kind < 2; kind++) {
    const char *kname = kind ? "per_process_user_time_100ms" : "per_job_user_time_100ms";
    double prev_end = -1, prev_q = -1, prev_i = -1;
    char gaps[256] = "", qgaps[256] = "", igaps[256] = "";
    size_t gl = 0, ql = 0, il = 0;
    for (int trial = 0; trial < 6; trial++) {
      HANDLE job;
      PROCESS_INFORMATION pi;
      DWORD err = 0;
      if (!start_limited_spinner(kind, &job, &pi, &err)) { emit("period_sequential", "\"limit\":\"%s\",\"trial\":%d,\"error\":%lu", kname, trial, (unsigned long)err); CloseHandle(job); continue; }
      double t_start = abs_ms();
      int exited = WaitForSingleObject(pi.hProcess, 25000) == WAIT_OBJECT_0;
      double t_end = abs_ms(), q_end = qpc_ms(), i_end = itime_ms();
      DWORD code = 0;
      GetExitCodeProcess(pi.hProcess, &code);
      FILETIME c, x, k, u;
      GetProcessTimes(pi.hProcess, &c, &x, &k, &u);
      ULARGE_INTEGER uu;
      uu.LowPart = u.dwLowDateTime; uu.HighPart = u.dwHighDateTime;
      emit("period_sequential", "\"limit\":\"%s\",\"trial\":%d,\"started_at_ms\":%.1f,\"ended_at_ms\":%.1f,\"lived_ms\":%.1f,\"killed\":%s,\"exit_code\":\"0x%08lX\",\"user_ms\":%.1f",
           kname, trial, t_start - t_prog, t_end - t_prog, t_end - t_start, bstr(exited), (unsigned long)code, (double)uu.QuadPart / 10000.0);
      if (exited && prev_end >= 0) {
        gl += (size_t)snprintf(gaps + gl, sizeof gaps - gl, "%s%.1f", gl ? "," : "", t_end - prev_end);
        ql += (size_t)snprintf(qgaps + ql, sizeof qgaps - ql, "%s%.1f", ql ? "," : "", q_end - prev_q);
        il += (size_t)snprintf(igaps + il, sizeof igaps - il, "%s%.1f", il ? "," : "", i_end - prev_i);
      }
      prev_end = exited ? t_end : -1;
      prev_q = exited ? q_end : -1;
      prev_i = exited ? i_end : -1;
      kill_close(&pi);
      CloseHandle(job);
    }
    emit("period_sequential_summary", "\"limit\":\"%s\",\"ms_between_successive_kills\":\"%s\",\"same_by_qpc\":\"%s\",\"same_by_interrupt_time\":\"%s\"",
         kname, gaps, qgaps, igaps);
  }
  /* two jobs 2.5 s apart (one job limit, one per-process limit): one pass kills both at once, a per-job timer would not */
  HANDLE ja, jb;
  PROCESS_INFORMATION pa, pb;
  DWORD ea = 0, eb = 0;
  int oka = start_limited_spinner(0, &ja, &pa, &ea);
  double ta = abs_ms();
  Sleep(2500);
  int okb = start_limited_spinner(1, &jb, &pb, &eb);
  double tb = abs_ms();
  double enda = -1, endb = -1;
  while (abs_ms() - ta < 25000 && ((oka && enda < 0) || (okb && endb < 0))) {
    if (oka && enda < 0 && WaitForSingleObject(pa.hProcess, 0) == WAIT_OBJECT_0) enda = abs_ms();
    if (okb && endb < 0 && WaitForSingleObject(pb.hProcess, 0) == WAIT_OBJECT_0) endb = abs_ms();
    Sleep(2);
  }
  emit("period_concurrent_job_limit_and_process_limit",
       "\"a_job_limit_started_ms\":%.1f,\"b_process_limit_started_ms\":%.1f,\"a_ended_ms\":%.1f,\"b_ended_ms\":%.1f,\"ends_ms_apart\":%.1f,\"setup_errors\":\"%lu/%lu\"",
       0.0, tb - ta, enda >= 0 ? enda - ta : -1.0, endb >= 0 ? endb - ta : -1.0, (enda >= 0 && endb >= 0) ? endb - enda : -1.0, (unsigned long)ea, (unsigned long)eb);
  if (oka) kill_close(&pa);
  if (okb) kill_close(&pb);
  CloseHandle(ja);
  CloseHandle(jb);
  double t_all = abs_ms() - t_prog, q_all = qpc_ms() - q_prog, i_all = i_prog >= 0 ? itime_ms() - i_prog : -1;
  emit("period_clock_rates", "\"system_time_ms\":%.1f,\"qpc_ms\":%.1f,\"interrupt_time_ms\":%.1f,\"system_per_qpc\":%.6f,\"interrupt_per_qpc\":%.6f",
       t_all, q_all, i_all, t_all / q_all, i_all >= 0 ? i_all / q_all : -1.0);
}

/* ------------------------------------------------------------------ pipes and stdio */
static int child_write_stdout(int total) {
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  if (h == NULL) return 0x20000;
  if (h == INVALID_HANDLE_VALUE) return 0x20001;
  char b[4096];
  memset(b, 'o', sizeof b);
  for (int done = 0; done < total; done += (int)sizeof b) {
    DWORD w;
    if (!WriteFile(h, b, sizeof b, &w, NULL)) return (int)(0x10000u | GetLastError());
  }
  return 0;
}

static int child_read_stdin(void) {
  HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
  char b[16];
  DWORD n = 0;
  BOOL ok = ReadFile(h, b, sizeof b, &n, NULL);
  return ok ? (int)(0x30000u | n) : (int)(0x38000u | GetLastError());
}

/* start this executable with the given std handles (only those inherited); flags passed through */
static BOOL spawn_with_std(const wchar_t *args, HANDLE in, HANDLE out, HANDLE err, PROCESS_INFORMATION *pi) {
  wchar_t cmd[4096];
  swprintf(cmd, sizeof cmd / sizeof cmd[0], L"\"%ls\" %ls", g_self, args);
  STARTUPINFOW si;
  memset(&si, 0, sizeof si);
  si.cb = sizeof si;
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = in;
  si.hStdOutput = out;
  si.hStdError = err;
  return CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, pi);
}

typedef struct { HANDLE h; volatile LONG written; } fill_t;
static DWORD WINAPI filler(LPVOID p) {
  fill_t *f = (fill_t *)p;
  char c = 'x';
  DWORD w;
  while (WriteFile(f->h, &c, 1, &w, NULL)) InterlockedIncrement(&f->written);
  return 0;
}

static void pipe_capacity(DWORD requested) {
  HANDLE r, w;
  CreatePipe(&r, &w, NULL, requested);
  fill_t f = {w, 0};
  HANDLE t = CreateThread(NULL, 0, filler, &f, 0, NULL);
  LONG last = -1;
  for (int i = 0; i < 100; i++) { Sleep(30); LONG now = f.written; if (now == last) break; last = now; }
  char name[64];
  snprintf(name, sizeof name, "pipe_capacity_nsize_%lu", (unsigned long)requested);
  emit(name, "\"bytes_before_writer_blocked\":%ld", (long)f.written);
  CancelSynchronousIo(t);
  CloseHandle(r);
  WaitForSingleObject(t, 2000);
  CloseHandle(t);
  CloseHandle(w);
}

static void probe_pipes(void) {
  pipe_capacity(0);
  pipe_capacity(4096);
  pipe_capacity(65536);
  pipe_capacity(1 << 20);

  SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
  /* wait-before-read: a child writing 1 MiB cannot exit while nobody drains its stdout */
  {
    HANDLE r, w;
    CreatePipe(&r, &w, &sa, 0);
    SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0);
    PROCESS_INFORMATION pi;
    BOOL ok = spawn_with_std(L"--child-write-stdout 1048576", NULL, w, NULL, &pi);
    CloseHandle(w);
    int exited;
    wait_exit(pi.hProcess, 1500, &exited);
    char b[65536];
    DWORD n;
    long got = 0;
    double t0 = abs_ms();
    while (ReadFile(r, b, sizeof b, &n, NULL) && n) got += n;
    DWORD last = GetLastError();
    int ex2;
    DWORD code = wait_exit(pi.hProcess, 3000, &ex2);
    emit("child_writes_1MiB_while_supervisor_waits_first", "\"spawn_ok\":%s,\"exited_within_1500ms_without_reading\":%s,\"bytes_read_after\":%ld,\"ms_to_drain\":%.0f,"
         "\"read_end_error\":%lu,\"exit_code\":\"0x%08lX\"", bstr(ok), bstr(exited), got, abs_ms() - t0, (unsigned long)last, (unsigned long)code);
    kill_close(&pi);
    CloseHandle(r);
  }
  /* the supervisor closes its read end while the child writes; and the same with the read end leaked into the child */
  for (int leak = 0; leak < 2; leak++) {
    HANDLE r, w;
    CreatePipe(&r, &w, &sa, 0);
    if (!leak) SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0);
    PROCESS_INFORMATION pi;
    spawn_with_std(L"--child-write-stdout 1048576", NULL, w, NULL, &pi);
    CloseHandle(w);
    char b[4096];
    DWORD n;
    ReadFile(r, b, sizeof b, &n, NULL);
    CloseHandle(r);
    int exited;
    DWORD code = wait_exit(pi.hProcess, 2000, &exited);
    emit(leak ? "supervisor_closes_read_end_but_child_inherited_it" : "supervisor_closes_read_end",
         "\"child_exited_within_2s\":%s,\"exit_code\":\"0x%08lX\",\"note\":\"0x1xxxx = WriteFile failed with error xxxx (0xE8 = 232 ERROR_NO_DATA, 0x6D = 109 ERROR_BROKEN_PIPE)\"",
         bstr(exited), (unsigned long)(exited ? code : 0));
    kill_close(&pi);
  }
  /* no stdout at all */
  {
    PROCESS_INFORMATION pi;
    spawn_with_std(L"--child-write-stdout 4096", NULL, NULL, NULL, &pi);
    int exited;
    DWORD code = wait_exit(pi.hProcess, 3000, &exited);
    emit("child_started_without_std_handles", "\"exit_code\":\"0x%08lX\",\"note\":\"0x20000 = GetStdHandle returned NULL; 0x1xxxx = WriteFile error xxxx\"", (unsigned long)code);
    kill_close(&pi);
  }
  /* stdin: the supervisor closes the write end */
  {
    HANDLE r, w;
    CreatePipe(&r, &w, &sa, 0);
    SetHandleInformation(w, HANDLE_FLAG_INHERIT, 0);
    PROCESS_INFORMATION pi;
    spawn_with_std(L"--child-read-stdin", r, NULL, NULL, &pi);
    CloseHandle(r);
    Sleep(100);
    CloseHandle(w);
    int exited;
    DWORD code = wait_exit(pi.hProcess, 3000, &exited);
    emit("supervisor_closes_child_stdin", "\"exit_code\":\"0x%08lX\",\"note\":\"0x3000n = ReadFile succeeded with n bytes; 0x38xxx = ReadFile failed with error xxx (0x6D = 109 ERROR_BROKEN_PIPE)\"",
         (unsigned long)code);
    kill_close(&pi);
  }
}

/* ------------------------------------------------------------------ pid reuse */
static void probe_pidreuse(void) {
  enum { N = 600 };
  static DWORD pids[N];
  int first_repeat = -1, repeat_of = -1;
  double t0 = abs_ms();
  for (int i = 0; i < N; i++) {
    PROCESS_INFORMATION pi;
    DWORD e;
    if (!spawn_self(L"--child-sleep 0", 0, NULL, &pi, &e)) { pids[i] = 0; continue; }
    WaitForSingleObject(pi.hProcess, 5000);
    pids[i] = pi.dwProcessId;
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    if (first_repeat < 0) for (int k = 0; k < i; k++) if (pids[k] == pids[i]) { first_repeat = i; repeat_of = k; break; }
  }
  double dt = abs_ms() - t0;
  int distinct = 0;
  for (int i = 0; i < N; i++) { int seen = 0; for (int k = 0; k < i; k++) if (pids[k] == pids[i]) { seen = 1; break; } if (!seen) distinct++; }
  emit("pid_reuse_spawn_wait_close", "\"children\":%d,\"distinct_pids\":%d,\"first_repeat_at_child\":%d,\"it_reused_the_pid_of_child\":%d,\"seconds\":%.1f",
       N, distinct, first_repeat, repeat_of, dt / 1000.0);

  /* an open handle to an exited process keeps its pid out of circulation */
  PROCESS_INFORMATION held;
  DWORD e;
  spawn_self(L"--child-sleep 0", 0, NULL, &held, &e);
  WaitForSingleObject(held.hProcess, 5000);
  DWORD held_pid = held.dwProcessId;
  int reissued_while_held = 0, reissued_after_close = 0, after_index = -1;
  for (int i = 0; i < N; i++) {
    PROCESS_INFORMATION pi;
    if (!spawn_self(L"--child-sleep 0", 0, NULL, &pi, &e)) continue;
    WaitForSingleObject(pi.hProcess, 5000);
    if (pi.dwProcessId == held_pid) reissued_while_held++;
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
  }
  CloseHandle(held.hProcess); CloseHandle(held.hThread);
  for (int i = 0; i < N; i++) {
    PROCESS_INFORMATION pi;
    if (!spawn_self(L"--child-sleep 0", 0, NULL, &pi, &e)) continue;
    WaitForSingleObject(pi.hProcess, 5000);
    if (pi.dwProcessId == held_pid) { reissued_after_close++; if (after_index < 0) after_index = i; }
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
  }
  emit("pid_held_by_an_open_handle", "\"held_pid\":%lu,\"reissued_while_handle_open\":%d,\"reissued_after_handle_closed\":%d,\"first_reissue_after_close_at_child\":%d,\"children_each_phase\":%d",
       (unsigned long)held_pid, reissued_while_held, reissued_after_close, after_index, N);
}

/* ------------------------------------------------------------------ round 2: suspend/freeze, WM_CLOSE, AppContainer, emulation, scale */

static double proc_cpu_ms(HANDLE h) {
  FILETIME c, x, k, u;
  if (!GetProcessTimes(h, &c, &x, &k, &u)) return -1;
  return ft_ms(k) + ft_ms(u);
}

static double cpu_over(HANDLE h, DWORD ms) {
  double a = proc_cpu_ms(h);
  Sleep(ms);
  return proc_cpu_ms(h) - a;
}

static double job_cpu_ms(HANDLE job) {
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION b;
  if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &b, sizeof b, NULL)) return -1;
  return (double)(b.TotalUserTime.QuadPart + b.TotalKernelTime.QuadPart) / 10000.0;
}

static double job_cpu_over(HANDLE job, DWORD ms) {
  double a = job_cpu_ms(job);
  Sleep(ms);
  return job_cpu_ms(job) - a;
}

static DWORD WINAPI spin_thread(LPVOID p) {
  (void)p;
  volatile unsigned long x = 0;
  for (;;) x++;
  return 0;
}

/* creates a new spinning thread about every millisecond: a process whose thread list keeps changing */
static int child_thread_spawner(void) {
  for (int i = 0; i < 400; i++) {
    HANDLE t = CreateThread(NULL, 0, spin_thread, NULL, 0, NULL);
    if (t) CloseHandle(t);
    double end = qpc_ms() + 1.0;
    while (qpc_ms() < end) {}
  }
  Sleep(60000);
  return 0;
}

typedef LONG(NTAPI *PFN_NtProc)(HANDLE);
typedef struct { ULONG Flags; BOOLEAN Freeze; BOOLEAN Swap; UCHAR Reserved0[2]; ULONG HighEdgeFilter; ULONG LowEdgeFilter; } MY_FREEZE_INFO;

/* suspends every thread of pid that Toolhelp lists; returns how many were suspended */
static int suspend_threads_of(DWORD pid, HANDLE *kept, int cap) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE) return 0;
  THREADENTRY32 te;
  te.dwSize = sizeof te;
  int n = 0;
  if (Thread32First(snap, &te)) {
    do {
      if (te.th32OwnerProcessID != pid) continue;
      HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
      if (!t) continue;
      if (SuspendThread(t) != (DWORD)-1 && n < cap) kept[n++] = t; else CloseHandle(t);
    } while (Thread32Next(snap, &te));
  }
  CloseHandle(snap);
  return n;
}

static int thread_count_of(DWORD pid) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE) return -1;
  THREADENTRY32 te;
  te.dwSize = sizeof te;
  int n = 0;
  if (Thread32First(snap, &te)) { do { if (te.th32OwnerProcessID == pid) n++; } while (Thread32Next(snap, &te)); }
  CloseHandle(snap);
  return n;
}

static void suspend_race(const char *name, int method) { /* 0 NtSuspendProcess, 1 one Toolhelp pass, 2 Toolhelp passes until the list is stable */
  PFN_NtProc nts = (PFN_NtProc)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSuspendProcess");
  const int trials = 8;
  int leaked = 0;
  double worst = 0, sum_threads_after = 0;
  for (int i = 0; i < trials; i++) {
    PROCESS_INFORMATION pi;
    DWORD err;
    if (!spawn_self(L"--child-thread-spawner", 0, NULL, &pi, &err)) { emit(name, "\"spawn_error\":%lu", (unsigned long)err); return; }
    Sleep(60 + 10 * i);
    HANDLE ths[1024];
    int suspended = 0;
    if (method == 0) nts(pi.hProcess);
    else if (method == 1) suspended = suspend_threads_of(pi.dwProcessId, ths, 1024);
    else {
      int rounds = 0, got;
      HANDLE tmp[1024];
      do { got = suspend_threads_of(pi.dwProcessId, tmp, 1024); suspended += got; rounds++; } while (got > 0 && rounds < 6);
      /* the second pass suspends the already suspended threads again (count 2); that only matters for the later resume */
    }
    (void)suspended;
    Sleep(30);
    double d = cpu_over(pi.hProcess, 200);
    sum_threads_after += thread_count_of(pi.dwProcessId);
    if (d > 30) leaked++;
    if (d > worst) worst = d;
    kill_close(&pi);
  }
  emit(name, "\"trials\":%d,\"trials_where_a_thread_kept_running\":%d,\"worst_cpu_ms_in_200ms_after_suspend\":%.0f,\"avg_threads_after\":%.0f", trials, leaked, worst, sum_threads_after / trials);
}

static void job_freeze_case(void) {
  HANDLE job = CreateJobObjectW(NULL, NULL);
  PROCESS_INFORMATION pi, pi2;
  DWORD err;
  if (!spawn_self(L"--child-spin", CREATE_SUSPENDED, NULL, &pi, &err)) { emit("job_freeze", "\"spawn_error\":%lu", (unsigned long)err); return; }
  AssignProcessToJobObject(job, pi.hProcess);
  ResumeThread(pi.hThread);
  Sleep(200);
  double running = job_cpu_over(job, 300);
  MY_FREEZE_INFO fi;
  memset(&fi, 0, sizeof fi);
  fi.Flags = 1;
  fi.Freeze = TRUE;
  SetLastError(0);
  BOOL ok = SetInformationJobObject(job, (JOBOBJECTINFOCLASS)18, &fi, sizeof fi);
  DWORD e16 = ok ? 0 : GetLastError();
  DWORD e8 = 0;
  if (!ok) {
    ok = SetInformationJobObject(job, (JOBOBJECTINFOCLASS)18, &fi, 8);
    e8 = ok ? 0 : GetLastError();
  }
  if (!ok) {
    emit("job_freeze", "\"set_ok\":false,\"error_with_16_byte_struct\":%lu,\"error_with_8_byte_struct\":%lu,\"cpu_ms_in_300ms_before\":%.0f", (unsigned long)e16, (unsigned long)e8, running);
    TerminateJobObject(job, 1);
    kill_close(&pi);
    CloseHandle(job);
    return;
  }
  Sleep(50);
  double frozen = job_cpu_over(job, 300);
  /* a process that joins a frozen job */
  double joined_cpu = -1;
  if (spawn_self(L"--child-spin", CREATE_SUSPENDED, NULL, &pi2, &err)) {
    BOOL as = AssignProcessToJobObject(job, pi2.hProcess);
    ResumeThread(pi2.hThread);
    Sleep(100);
    joined_cpu = as ? cpu_over(pi2.hProcess, 300) : -2;
  }
  fi.Freeze = FALSE;
  BOOL th = SetInformationJobObject(job, (JOBOBJECTINFOCLASS)18, &fi, sizeof fi);
  Sleep(50);
  double thawed = job_cpu_over(job, 300);
  fi.Freeze = TRUE;
  SetInformationJobObject(job, (JOBOBJECTINFOCLASS)18, &fi, sizeof fi);
  Sleep(50);
  double t0 = abs_ms();
  TerminateJobObject(job, 9);
  int died = WaitForSingleObject(pi.hProcess, 5000) == WAIT_OBJECT_0;
  double ms = abs_ms() - t0;
  DWORD code = 0;
  GetExitCodeProcess(pi.hProcess, &code);
  emit("job_freeze",
       "\"set_ok\":true,\"cpu_ms_in_300ms_running\":%.0f,\"cpu_ms_in_300ms_frozen\":%.0f,\"cpu_ms_in_300ms_of_a_process_added_to_the_frozen_job\":%.0f,\"unfreeze_ok\":%s,\"cpu_ms_in_300ms_after_unfreeze\":%.0f,"
       "\"terminate_job_while_frozen_killed_it\":%s,\"ms_to_exit\":%.0f,\"exit_code\":%lu",
       running, frozen, joined_cpu, bstr(th), thawed, bstr(died), ms, (unsigned long)code);
  kill_close(&pi);
  if (pi2.hProcess) kill_close(&pi2);
  CloseHandle(job);
}

static void probe_suspend(void) {
  HMODULE nt = GetModuleHandleW(L"ntdll.dll");
  PFN_NtProc nts = (PFN_NtProc)(void *)GetProcAddress(nt, "NtSuspendProcess");
  PFN_NtProc ntr = (PFN_NtProc)(void *)GetProcAddress(nt, "NtResumeProcess");
  PROCESS_INFORMATION pi;
  DWORD err;
  if (!nts || !ntr) { emit("nt_suspend_process", "\"error\":\"NtSuspendProcess/NtResumeProcess not found\""); }
  else if (!spawn_self(L"--child-spin", 0, NULL, &pi, &err)) { emit("nt_suspend_process", "\"spawn_error\":%lu", (unsigned long)err); }
  else {
    Sleep(200);
    double running = cpu_over(pi.hProcess, 300);
    LONG s1 = nts(pi.hProcess);
    Sleep(50);
    double suspended = cpu_over(pi.hProcess, 300);
    LONG s2 = nts(pi.hProcess);
    LONG r1 = ntr(pi.hProcess);
    Sleep(50);
    double after_one_resume = cpu_over(pi.hProcess, 300);
    LONG r2 = ntr(pi.hProcess);
    Sleep(50);
    double after_two_resumes = cpu_over(pi.hProcess, 300);
    LONG r3 = ntr(pi.hProcess); /* resume without a matching suspend */
    emit("nt_suspend_process",
         "\"cpu_ms_in_300ms_running\":%.0f,\"cpu_ms_in_300ms_suspended\":%.0f,\"cpu_ms_in_300ms_after_2_suspends_1_resume\":%.0f,\"cpu_ms_in_300ms_after_2_suspends_2_resumes\":%.0f,"
         "\"status_suspend\":\"0x%08lX\",\"status_second_suspend\":\"0x%08lX\",\"status_resume\":\"0x%08lX\",\"status_second_resume\":\"0x%08lX\",\"status_extra_resume\":\"0x%08lX\"",
         running, suspended, after_one_resume, after_two_resumes, (unsigned long)s1, (unsigned long)s2, (unsigned long)r1, (unsigned long)r2, (unsigned long)r3);
    nts(pi.hProcess);
    Sleep(50);
    double t0 = abs_ms();
    TerminateProcess(pi.hProcess, 7);
    int died = WaitForSingleObject(pi.hProcess, 5000) == WAIT_OBJECT_0;
    double ms = abs_ms() - t0;
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    emit("terminate_a_suspended_process", "\"exited\":%s,\"ms\":%.0f,\"exit_code\":%lu", bstr(died), ms, (unsigned long)code);
    kill_close(&pi);
  }

  /* a suspended-at-creation process: how many ResumeThread calls it takes */
  if (spawn_self(L"--child-spin", CREATE_SUSPENDED, NULL, &pi, &err)) {
    DWORD a = SuspendThread(pi.hThread); /* returns the previous count: 1 (CREATE_SUSPENDED) */
    DWORD b = ResumeThread(pi.hThread);  /* previous count 2 */
    DWORD c = ResumeThread(pi.hThread);  /* previous count 1 -> running */
    Sleep(100);
    double cpu = cpu_over(pi.hProcess, 200);
    emit("create_suspended_then_extra_suspend", "\"suspend_returned_previous_count\":%lu,\"resume_returned_previous_count\":[%lu,%lu],\"cpu_ms_in_200ms_after\":%.0f",
         (unsigned long)a, (unsigned long)b, (unsigned long)c, cpu);
    kill_close(&pi);
  }

  suspend_race("suspend_race_NtSuspendProcess", 0);
  suspend_race("suspend_race_one_Toolhelp_pass", 1);
  suspend_race("suspend_race_Toolhelp_passes_until_stable", 2);
  job_freeze_case();
}

/* ------------------------------------------------------------------ WM_CLOSE and taskkill */
static int g_wnd_mode;
static HANDLE g_wnd_log;
static LRESULT CALLBACK wnd_proc(HWND h, UINT m, WPARAM w, LPARAM l) {
  if (m == WM_CLOSE) {
    log_to(g_wnd_log, "got WM_CLOSE\n");
    if (g_wnd_mode == 0) DestroyWindow(h);
    return 0;
  }
  if (m == WM_QUERYENDSESSION) { log_to(g_wnd_log, "got WM_QUERYENDSESSION\n"); return TRUE; }
  if (m == WM_ENDSESSION) { log_to(g_wnd_log, "got WM_ENDSESSION\n"); return 0; }
  if (m == WM_DESTROY) { PostQuitMessage(77); return 0; }
  return DefWindowProcW(h, m, w, l);
}

static int child_window(const wchar_t *mode, const wchar_t *logpath) {
  g_wnd_log = open_log(logpath);
  g_wnd_mode = wcscmp(mode, L"ignores") == 0;
  WNDCLASSW wc;
  memset(&wc, 0, sizeof wc);
  wc.lpfnWndProc = wnd_proc;
  wc.hInstance = GetModuleHandleW(NULL);
  wc.lpszClassName = L"ProcExploreWindow";
  RegisterClassW(&wc);
  HWND h = CreateWindowExW(0, wc.lpszClassName, L"probe", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL, wc.hInstance, NULL);
  if (!h) {
    log_to(g_wnd_log, "window_error=%lu\nready\n", (unsigned long)GetLastError());
    Sleep(60000);
    return 3;
  }
  log_to(g_wnd_log, "ready window_created\n");
  if (wcscmp(mode, L"hung") == 0) { Sleep(60000); return 0; } /* never pumps messages */
  MSG msg;
  while (GetMessageW(&msg, NULL, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessageW(&msg); }
  return (int)msg.wParam;
}

typedef struct { DWORD pid; HWND found[8]; int n; } enum_t;
static BOOL CALLBACK enum_cb(HWND h, LPARAM p) {
  enum_t *e = (enum_t *)p;
  DWORD pid = 0;
  GetWindowThreadProcessId(h, &pid);
  if (pid == e->pid && e->n < 8) e->found[e->n++] = h;
  return TRUE;
}

static int run_cmdline(const wchar_t *cmdline, DWORD ms, DWORD *code) {
  wchar_t cmd[2048];
  swprintf(cmd, sizeof cmd / sizeof cmd[0], L"%ls", cmdline);
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  memset(&si, 0, sizeof si);
  si.cb = sizeof si;
  if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) { *code = GetLastError(); return 0; }
  int ok = WaitForSingleObject(pi.hProcess, ms) == WAIT_OBJECT_0;
  GetExitCodeProcess(pi.hProcess, code);
  if (!ok) TerminateProcess(pi.hProcess, 1);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return ok;
}

static void wm_case(const char *name, const wchar_t *mode, int do_hung_timing) {
  wchar_t log[MAX_PATH * 2], args[1024];
  swprintf(log, MAX_PATH * 2, L"%ls\\wm-%ls.log", g_tmp, mode);
  DeleteFileW(log);
  swprintf(args, 1024, L"--child-window %ls \"%ls\"", mode, log);
  PROCESS_INFORMATION pi;
  DWORD err;
  if (!spawn_self(args, 0, NULL, &pi, &err)) { emit(name, "\"spawn_error\":%lu", (unsigned long)err); return; }
  int ready = wait_ready(log, pi.hProcess, 6000);
  char b[512];
  read_text(log, b, sizeof b);
  enum_t e;
  memset(&e, 0, sizeof e);
  e.pid = pi.dwProcessId;
  EnumWindows(enum_cb, (LPARAM)&e);
  char wnd_err[48] = "";
  char *we = strstr(b, "window_error=");
  if (we) snprintf(wnd_err, sizeof wnd_err, "%.20s", we + 13), wnd_err[strcspn(wnd_err, "\r\n")] = 0;
  if (do_hung_timing && e.n > 0) {
    /* a thread that does not pump messages: SendMessageTimeout waits for its timeout until Windows calls the window hung (5 s) */
    DWORD_PTR res;
    int hung0 = IsHungAppWindow(e.found[0]);
    double a = abs_ms();
    LRESULT r0 = SendMessageTimeoutW(e.found[0], WM_NULL, 0, 0, SMTO_ABORTIFHUNG, 1000, &res);
    double t_first = abs_ms() - a;
    DWORD e0 = r0 ? 0 : GetLastError();
    Sleep(6000);
    int hung1 = IsHungAppWindow(e.found[0]);
    a = abs_ms();
    LRESULT r1 = SendMessageTimeoutW(e.found[0], WM_NULL, 0, 0, SMTO_ABORTIFHUNG, 1000, &res);
    double t_second = abs_ms() - a;
    DWORD e1 = r1 ? 0 : GetLastError();
    emit(name, "\"windows_found\":%d,\"IsHungAppWindow_at_start\":%s,\"SendMessageTimeout_WM_NULL_returned\":%s,\"first_call_ms\":%.0f,\"first_error\":%lu,\"IsHungAppWindow_after_6s\":%s,\"second_call_returned\":%s,\"second_call_ms\":%.0f,\"second_error\":%lu",
         e.n, bstr(hung0), bstr(r0 != 0), t_first, (unsigned long)e0, bstr(hung1), bstr(r1 != 0), t_second, (unsigned long)e1);
    kill_close(&pi);
    return;
  }
  double t0 = abs_ms();
  if (e.n > 0) PostMessageW(e.found[0], WM_CLOSE, 0, 0);
  int exited = WaitForSingleObject(pi.hProcess, 1500) == WAIT_OBJECT_0;
  double ms = abs_ms() - t0;
  DWORD code = 0;
  GetExitCodeProcess(pi.hProcess, &code);
  read_text(log, b, sizeof b);
  for (char *c = b; *c; c++) if (*c == '\r' || *c == '\n') *c = ';';
  emit(name, "\"ready\":%s,\"top_level_windows_of_the_process\":%d,\"window_create_error\":\"%s\",\"WM_CLOSE_posted\":%s,\"exited_within_1500ms\":%s,\"ms\":%.0f,\"exit_code\":%lu,\"child_log\":\"%.100s\"",
       bstr(ready), e.n, wnd_err, bstr(e.n > 0), bstr(exited), ms, (unsigned long)code, b);
  kill_close(&pi);
}

static void taskkill_case(const char *name, const wchar_t *child_args) {
  PROCESS_INFORMATION pi;
  DWORD err;
  if (!spawn_self(child_args, 0, NULL, &pi, &err)) { emit(name, "\"spawn_error\":%lu", (unsigned long)err); return; }
  Sleep(1000);
  wchar_t out[MAX_PATH * 2], cmd[2048];
  swprintf(out, MAX_PATH * 2, L"%ls\\taskkill.txt", g_tmp);
  swprintf(cmd, 2048, L"cmd.exe /c taskkill /PID %lu > \"%ls\" 2>&1", (unsigned long)pi.dwProcessId, out);
  DWORD code = 0;
  double t0 = abs_ms();
  int finished = run_cmdline(cmd, 15000, &code);
  int exited = WaitForSingleObject(pi.hProcess, 1500) == WAIT_OBJECT_0;
  double ms = abs_ms() - t0;
  char b[512];
  read_text(out, b, sizeof b);
  for (char *c = b; *c; c++) if (*c == '\r' || *c == '\n') *c = ' ';
  emit(name, "\"taskkill_finished\":%s,\"taskkill_exit_code\":%lu,\"child_exited\":%s,\"ms\":%.0f,\"taskkill_said\":\"%.160s\"", bstr(finished), (unsigned long)code, bstr(exited), ms, b);
  kill_close(&pi);
}

static void probe_wmclose(void) {
  HWINSTA ws = GetProcessWindowStation();
  char wsn[64] = "?", dn[64] = "?";
  DWORD n;
  if (ws) GetUserObjectInformationA(ws, UOI_NAME, wsn, sizeof wsn, &n);
  HDESK d = GetThreadDesktop(GetCurrentThreadId());
  if (d) GetUserObjectInformationA(d, UOI_NAME, dn, sizeof dn, &n);
  DWORD sid = 0;
  ProcessIdToSessionId(GetCurrentProcessId(), &sid);
  emit("desktop", "\"session_id\":%lu,\"window_station\":\"%s\",\"desktop\":\"%s\"", (unsigned long)sid, wsn, dn);
  wm_case("window_child_closes_on_WM_CLOSE", L"closes", 0);
  wm_case("window_child_ignores_WM_CLOSE", L"ignores", 0);
  wm_case("window_child_that_never_pumps_messages", L"hung", 1);
  taskkill_case("taskkill_without_F_on_a_console_child", L"--child-sleep 30000");
  /* a window child for taskkill: reuse the closing mode */
  {
    wchar_t log[MAX_PATH * 2], args[1024];
    swprintf(log, MAX_PATH * 2, L"%ls\\wm-tk.log", g_tmp);
    DeleteFileW(log);
    swprintf(args, 1024, L"--child-window closes \"%ls\"", log);
    taskkill_case("taskkill_without_F_on_a_window_child", args);
  }
}

/* ------------------------------------------------------------------ AppContainer */
typedef HRESULT(WINAPI *PFN_CreateAppContainerProfile)(PCWSTR, PCWSTR, PCWSTR, PSID_AND_ATTRIBUTES, DWORD, PSID *);
typedef HRESULT(WINAPI *PFN_DeriveAppContainerSid)(PCWSTR, PSID *);
typedef HRESULT(WINAPI *PFN_DeleteAppContainerProfile)(PCWSTR);
typedef struct { PSID AppContainerSid; PSID_AND_ATTRIBUTES Capabilities; DWORD CapabilityCount; DWORD Reserved; } MY_SECCAP;
#define MY_ATTR_SECURITY_CAPABILITIES 0x00020009

static int try_write(const wchar_t *dir, const wchar_t *name, DWORD *err) {
  wchar_t p[MAX_PATH * 2];
  swprintf(p, MAX_PATH * 2, L"%ls\\%ls", dir, name);
  HANDLE h = CreateFileW(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
  if (h == INVALID_HANDLE_VALUE) { *err = GetLastError(); return 0; }
  CloseHandle(h);
  *err = 0;
  return 1;
}

static int child_ac(const wchar_t *logpath, DWORD supervisor_pid, int port) {
  HANDLE log = open_log(logpath);
  char o[3000];
  size_t l = 0;
#define ADD(...) l += (size_t)snprintf(o + l, sizeof o - l, __VA_ARGS__)
  ADD("{");
  HANDLE tok = NULL;
  OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok);
  DWORD isac = 0, n = 0;
  if (tok) GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)29, &isac, sizeof isac, &n); /* TokenIsAppContainer */
  ADD("\"token_is_app_container\":%lu", (unsigned long)isac);
  if (tok) {
    BYTE buf[256];
    if (GetTokenInformation(tok, TokenIntegrityLevel, buf, sizeof buf, &n)) {
      PSID s = ((TOKEN_MANDATORY_LABEL *)buf)->Label.Sid;
      ADD(",\"integrity_rid\":\"0x%lX\"", (unsigned long)*GetSidSubAuthority(s, *GetSidSubAuthorityCount(s) - 1));
    }
    CloseHandle(tok);
  }
  BOOL injob = FALSE;
  IsProcessInJob(GetCurrentProcess(), NULL, &injob);
  ADD(",\"in_a_job\":%s", bstr(injob));

  wchar_t scratch[MAX_PATH * 2];
  wcscpy(scratch, logpath);
  wchar_t *bs = wcsrchr(scratch, L'\\');
  if (bs) *bs = 0;
  DWORD e;
  int ok = try_write(scratch, L"ac-write-test.tmp", &e);
  ADD(",\"write_to_granted_scratch_dir\":\"%s\"", ok ? "ok" : "denied");
  if (!ok) ADD(",\"scratch_error\":%lu", (unsigned long)e);
  ok = try_write(L"C:\\Users\\Public", L"ac-write-test.tmp", &e);
  ADD(",\"write_to_C_Users_Public\":\"%s\",\"public_error\":%lu", ok ? "ok" : "denied", (unsigned long)e);
  ok = try_write(L"C:\\Windows\\Temp", L"ac-write-test.tmp", &e);
  ADD(",\"write_to_C_Windows_Temp\":\"%s\",\"windows_temp_error\":%lu", ok ? "ok" : "denied", (unsigned long)e);
  wchar_t tmp[MAX_PATH * 2];
  GetTempPathW(MAX_PATH * 2, tmp);
  size_t tl = wcslen(tmp);
  if (tl > 0 && tmp[tl - 1] == L'\\') tmp[tl - 1] = 0;
  ok = try_write(tmp, L"ac-write-test.tmp", &e);
  ADD(",\"write_to_own_GetTempPath\":\"%s\",\"temp_error\":%lu", ok ? "ok" : "denied", (unsigned long)e);

  /* the supervisor */
  HANDLE sp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, supervisor_pid);
  ADD(",\"open_supervisor_query_limited\":\"%s\",\"error1\":%lu", sp ? "ok" : "denied", (unsigned long)(sp ? 0 : GetLastError()));
  if (sp) CloseHandle(sp);
  sp = OpenProcess(SYNCHRONIZE, FALSE, supervisor_pid);
  ADD(",\"open_supervisor_synchronize\":\"%s\",\"error2\":%lu", sp ? "ok" : "denied", (unsigned long)(sp ? 0 : GetLastError()));
  if (sp) CloseHandle(sp);
  sp = OpenProcess(PROCESS_TERMINATE, FALSE, supervisor_pid);
  ADD(",\"open_supervisor_terminate\":\"%s\",\"error3\":%lu", sp ? "ok" : "denied", (unsigned long)(sp ? 0 : GetLastError()));
  if (sp) CloseHandle(sp);

  /* network */
  WSADATA wd;
  WSAStartup(MAKEWORD(2, 2), &wd);
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  struct sockaddr_in a;
  memset(&a, 0, sizeof a);
  a.sin_family = AF_INET;
  a.sin_port = htons((u_short)port);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  /* non-blocking with a 3 s limit: a filter that drops the packets would otherwise hold connect() for ~21 s */
  u_long nb = 1;
  ioctlsocket(s, FIONBIO, &nb);
  double tc = abs_ms();
  int rc = connect(s, (struct sockaddr *)&a, sizeof a);
  int werr = rc == 0 ? 0 : WSAGetLastError();
  const char *verdict = rc == 0 ? "connected" : "?";
  if (rc != 0 && werr == WSAEWOULDBLOCK) {
    fd_set wf, ef;
    FD_ZERO(&wf); FD_ZERO(&ef);
    FD_SET(s, &wf); FD_SET(s, &ef);
    struct timeval tv = {3, 0};
    int sel = select(0, NULL, &wf, &ef, &tv);
    if (sel == 0) { verdict = "no answer within 3 s (packets dropped)"; werr = 0; }
    else if (FD_ISSET(s, &wf)) { verdict = "connected"; werr = 0; }
    else { int soerr = 0, sl = sizeof soerr; getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &sl); verdict = "refused"; werr = soerr; }
  } else if (rc != 0) verdict = "failed at once";
  ADD(",\"connect_to_supervisors_loopback_listener\":\"%s\",\"wsa_error\":%d,\"connect_ms\":%.0f", verdict, werr, abs_ms() - tc);
  closesocket(s);

  /* a grandchild */
  PROCESS_INFORMATION gp;
  DWORD ge;
  int gok = spawn_self(L"--child-sleep 300", 0, NULL, &gp, &ge);
  BOOL gjob = FALSE;
  if (gok) { IsProcessInJob(gp.hProcess, NULL, &gjob); WaitForSingleObject(gp.hProcess, 3000); CloseHandle(gp.hProcess); CloseHandle(gp.hThread); }
  ADD(",\"create_grandchild\":\"%s\",\"grandchild_error\":%lu,\"grandchild_in_a_job\":%s", gok ? "ok" : "failed", (unsigned long)(gok ? 0 : ge), bstr(gjob));

  /* its own job */
  HANDLE job = CreateJobObjectW(NULL, NULL);
  BOOL as = job ? AssignProcessToJobObject(job, GetCurrentProcess()) : FALSE;
  ADD(",\"create_job_object\":%s,\"assign_self_to_a_nested_job\":%s,\"assign_error\":%lu}", bstr(job != NULL), bstr(as), (unsigned long)(as ? 0 : GetLastError()));
#undef ADD
  log_to(log, "ready\n%s\n", o);
  return 0;
}

static void probe_appcontainer(void) {
  HMODULE ue = LoadLibraryW(L"userenv.dll");
  PFN_CreateAppContainerProfile create = ue ? (PFN_CreateAppContainerProfile)(void *)GetProcAddress(ue, "CreateAppContainerProfile") : NULL;
  PFN_DeriveAppContainerSid derive = ue ? (PFN_DeriveAppContainerSid)(void *)GetProcAddress(ue, "DeriveAppContainerSidFromAppContainerName") : NULL;
  PFN_DeleteAppContainerProfile del = ue ? (PFN_DeleteAppContainerProfile)(void *)GetProcAddress(ue, "DeleteAppContainerProfile") : NULL;
  if (!create || !derive) { emit("app_container_profile", "\"error\":\"userenv.dll functions not found\""); return; }
  PSID sid = NULL;
  HRESULT hr = create(L"proc.explore.probe", L"proc explore", L"probe", NULL, 0, &sid);
  if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) hr = derive(L"proc.explore.probe", &sid);
  if (FAILED(hr) || !sid) { emit("app_container_profile", "\"error\":\"CreateAppContainerProfile failed\",\"hresult\":\"0x%08lX\"", (unsigned long)hr); return; }
  LPWSTR sidstr = NULL;
  ConvertSidToStringSidW(sid, &sidstr);
  emit("app_container_profile", "\"created\":true,\"sid\":\"%ls\"", sidstr ? sidstr : L"?");

  /* the container may read the program and write the scratch directory only if their ACLs say so */
  wchar_t exedir[MAX_PATH * 2], cmd[2048];
  wcscpy(exedir, g_self);
  wchar_t *bs = wcsrchr(exedir, L'\\');
  if (bs) *bs = 0;
  DWORD code = 0;
  swprintf(cmd, 2048, L"icacls.exe \"%ls\" /grant *%ls:(OI)(CI)(RX)", exedir, sidstr);
  run_cmdline(cmd, 20000, &code);
  DWORD code2 = 0;
  swprintf(cmd, 2048, L"icacls.exe \"%ls\" /grant *%ls:(OI)(CI)(F)", g_tmp, sidstr);
  run_cmdline(cmd, 20000, &code2);
  emit("app_container_acl", "\"icacls_exe_dir_exit\":%lu,\"icacls_scratch_dir_exit\":%lu", (unsigned long)code, (unsigned long)code2);

  /* listener on loopback: can the container connect to it */
  WSADATA wd;
  WSAStartup(MAKEWORD(2, 2), &wd);
  SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  struct sockaddr_in a;
  memset(&a, 0, sizeof a);
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bind(ls, (struct sockaddr *)&a, sizeof a);
  listen(ls, 4);
  int alen = sizeof a;
  getsockname(ls, (struct sockaddr *)&a, &alen);
  int port = ntohs(a.sin_port);

  wchar_t log[MAX_PATH * 2], args[1024], full[4096];
  swprintf(log, MAX_PATH * 2, L"%ls\\ac.log", g_tmp);
  DeleteFileW(log);
  swprintf(args, 1024, L"--child-ac \"%ls\" %lu %d", log, (unsigned long)GetCurrentProcessId(), port);
  swprintf(full, 4096, L"\"%ls\" %ls", g_self, args);

  SIZE_T asz = 0;
  InitializeProcThreadAttributeList(NULL, 1, 0, &asz);
  LPPROC_THREAD_ATTRIBUTE_LIST al = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, asz);
  InitializeProcThreadAttributeList(al, 1, 0, &asz);
  MY_SECCAP sc;
  memset(&sc, 0, sizeof sc);
  sc.AppContainerSid = sid;
  UpdateProcThreadAttribute(al, 0, MY_ATTR_SECURITY_CAPABILITIES, &sc, sizeof sc, NULL, NULL);
  STARTUPINFOEXW si;
  memset(&si, 0, sizeof si);
  si.StartupInfo.cb = sizeof si;
  si.lpAttributeList = al;
  PROCESS_INFORMATION pi;
  memset(&pi, 0, sizeof pi);
  HANDLE job = CreateJobObjectW(NULL, NULL);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION xl;
  memset(&xl, 0, sizeof xl);
  xl.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  SetInformationJobObject(job, JobObjectExtendedLimitInformation, &xl, sizeof xl);
  BOOL ok = CreateProcessW(NULL, full, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, g_tmp, &si.StartupInfo, &pi);
  DWORD err = ok ? 0 : GetLastError();
  if (!ok) {
    emit("app_container_child", "\"spawned\":false,\"error\":%lu", (unsigned long)err);
  } else {
    BOOL as = AssignProcessToJobObject(job, pi.hProcess);
    DWORD as_err = as ? 0 : GetLastError();
    ResumeThread(pi.hThread);
    int ready = wait_ready(log, pi.hProcess, 30000);
    int exited = WaitForSingleObject(pi.hProcess, 10000) == WAIT_OBJECT_0;
    DWORD ec = 0;
    GetExitCodeProcess(pi.hProcess, &ec);
    char b[4096];
    read_text(log, b, sizeof b);
    if (!ready) {
      /* what is it doing: CPU used and thread count tell a hang from a busy loop */
      emit("app_container_child_not_ready", "\"cpu_ms\":%.0f,\"threads\":%d", proc_cpu_ms(pi.hProcess), thread_count_of(pi.dwProcessId));
    }
    char *json = strchr(b, '{');
    if (json) { char *nl = strpbrk(json, "\r\n"); if (nl) *nl = 0; }
    emit("app_container_child", "\"spawned\":true,\"assigned_to_job\":%s,\"assign_error\":%lu,\"reported\":%s,\"exited\":%s,\"exit_code\":%lu,\"child_says\":%s",
         bstr(as), (unsigned long)as_err, bstr(ready), bstr(exited), (unsigned long)ec, json ? json : "null");
    /* the job still controls it */
    kill_close(&pi);
  }
  CloseHandle(job);
  closesocket(ls);
  DeleteProcThreadAttributeList(al);
  if (del) del(L"proc.explore.probe");
  LocalFree(sidstr);
}

/* ------------------------------------------------------------------ x64 and x86 children on arm64 */
static BOOL spawn_exe(const wchar_t *exe, const wchar_t *args, DWORD flags, PROCESS_INFORMATION *pi, DWORD *err) {
  wchar_t cmd[4096];
  swprintf(cmd, sizeof cmd / sizeof cmd[0], L"\"%ls\" %ls", exe, args);
  STARTUPINFOW si;
  memset(&si, 0, sizeof si);
  si.cb = sizeof si;
  memset(pi, 0, sizeof *pi);
  BOOL ok = CreateProcessW(NULL, cmd, NULL, NULL, FALSE, flags, NULL, NULL, &si, pi);
  *err = ok ? 0 : GetLastError();
  return ok;
}

static int child_arch(const wchar_t *logpath) {
  HANDLE log = open_log(logpath);
  typedef BOOL(WINAPI * PFN_IsWow64Process2)(HANDLE, USHORT *, USHORT *);
  PFN_IsWow64Process2 f = (PFN_IsWow64Process2)(void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
  USHORT pm = 0, nm = 0;
  if (f) f(GetCurrentProcess(), &pm, &nm);
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  wchar_t env[32] = L"";
  GetEnvironmentVariableW(L"PROCESSOR_ARCHITECTURE", env, 32);
  log_to(log, "ready {\"process_machine\":\"0x%04X\",\"native_machine\":\"0x%04X\",\"pointer_bits\":%d,\"GetSystemInfo_architecture\":%u,\"PROCESSOR_ARCHITECTURE\":\"%ls\"}\n",
         pm, nm, (int)sizeof(void *) * 8, si.wProcessorArchitecture, env);
  return 0;
}

static int child_alloc(int mb) {
  char *p = (char *)VirtualAlloc(NULL, (SIZE_T)mb << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!p) return (int)(0x10000u | GetLastError());
  for (SIZE_T i = 0; i < ((SIZE_T)mb << 20); i += 4096) p[i] = 1;
  return 0;
}

static void emulation_one(const char *label, const wchar_t *exe) {
  wchar_t log[MAX_PATH * 2], args[1024];
  swprintf(log, MAX_PATH * 2, L"%ls\\arch-%hs.log", g_tmp, label);
  DeleteFileW(log);
  swprintf(args, 1024, L"--child-arch \"%ls\"", log);
  PROCESS_INFORMATION pi;
  DWORD err;
  char name[96];
  snprintf(name, sizeof name, "%s_architecture", label);
  if (!spawn_exe(exe, args, 0, &pi, &err)) { emit(name, "\"spawn_error\":%lu", (unsigned long)err); return; }
  wait_ready(log, pi.hProcess, 10000);
  WaitForSingleObject(pi.hProcess, 5000);
  char b[512];
  read_text(log, b, sizeof b);
  char *json = strchr(b, '{');
  if (json) { char *nl = strpbrk(json, "\r\n"); if (nl) *nl = 0; }
  emit(name, "\"child_says\":%s", json ? json : "null");
  kill_close(&pi);

  /* job accounting and process-time limit with this child */
  HANDLE job = CreateJobObjectW(NULL, NULL);
  if (!spawn_exe(exe, L"--child-spin", CREATE_SUSPENDED, &pi, &err)) { emit(name, "\"spawn_error_spin\":%lu", (unsigned long)err); return; }
  AssignProcessToJobObject(job, pi.hProcess);
  ResumeThread(pi.hThread);
  Sleep(500);
  double job_cpu = job_cpu_ms(job);
  double proc_cpu = proc_cpu_ms(pi.hProcess);
  snprintf(name, sizeof name, "%s_job_accounting", label);
  emit(name, "\"cpu_ms_in_500ms_wall_by_job\":%.0f,\"by_process\":%.0f", job_cpu, proc_cpu);
  TerminateJobObject(job, 1);
  kill_close(&pi);
  CloseHandle(job);

  job = CreateJobObjectW(NULL, NULL);
  JOBOBJECT_BASIC_LIMIT_INFORMATION bl;
  memset(&bl, 0, sizeof bl);
  bl.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_TIME;
  bl.PerProcessUserTimeLimit.QuadPart = 100 * 10000LL;
  SetInformationJobObject(job, JobObjectBasicLimitInformation, &bl, sizeof bl);
  if (spawn_exe(exe, L"--child-spin", CREATE_SUSPENDED, &pi, &err)) {
    AssignProcessToJobObject(job, pi.hProcess);
    double t0 = abs_ms();
    ResumeThread(pi.hThread);
    int died = WaitForSingleObject(pi.hProcess, 20000) == WAIT_OBJECT_0;
    double ms = abs_ms() - t0;
    DWORD ec = 0;
    GetExitCodeProcess(pi.hProcess, &ec);
    snprintf(name, sizeof name, "%s_process_time_limit_100ms", label);
    emit(name, "\"killed\":%s,\"ms_until_killed\":%.0f,\"exit_code\":\"0x%08lX\"", bstr(died), ms, (unsigned long)ec);
    kill_close(&pi);
  }
  CloseHandle(job);

  /* per-process memory limit: 200 MiB; allocate 80 MiB (should fit) and 300 MiB (should not) */
  int mbs[2] = {80, 300};
  for (int i = 0; i < 2; i++) {
    job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION xl;
    memset(&xl, 0, sizeof xl);
    xl.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    xl.ProcessMemoryLimit = (SIZE_T)200 << 20;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &xl, sizeof xl);
    wchar_t aa[64];
    swprintf(aa, 64, L"--child-alloc %d", mbs[i]);
    if (spawn_exe(exe, aa, CREATE_SUSPENDED, &pi, &err)) {
      AssignProcessToJobObject(job, pi.hProcess);
      ResumeThread(pi.hThread);
      int done = WaitForSingleObject(pi.hProcess, 20000) == WAIT_OBJECT_0;
      DWORD ec = 0;
      GetExitCodeProcess(pi.hProcess, &ec);
      snprintf(name, sizeof name, "%s_process_memory_limit_200MiB_alloc_%dMiB", label, mbs[i]);
      emit(name, "\"finished\":%s,\"exit_code\":\"0x%08lX\"", bstr(done), (unsigned long)ec);
      kill_close(&pi);
    } else {
      snprintf(name, sizeof name, "%s_process_memory_limit_200MiB_alloc_%dMiB", label, mbs[i]);
      emit(name, "\"spawn_error\":%lu", (unsigned long)err);
    }
    CloseHandle(job);
  }
}

static void probe_emulation(void) {
  wchar_t x64[MAX_PATH * 2] = L"", x86[MAX_PATH * 2] = L"";
  GetEnvironmentVariableW(L"PROC_EXPLORE_X64", x64, MAX_PATH * 2);
  GetEnvironmentVariableW(L"PROC_EXPLORE_X86", x86, MAX_PATH * 2);
  USHORT pm = 0, nm = 0;
  typedef BOOL(WINAPI * PFN_IsWow64Process2)(HANDLE, USHORT *, USHORT *);
  PFN_IsWow64Process2 f = (PFN_IsWow64Process2)(void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
  if (f) f(GetCurrentProcess(), &pm, &nm);
  emit("emulation_environment", "\"this_process_machine\":\"0x%04X\",\"native_machine\":\"0x%04X\",\"x64_build_given\":%s,\"x86_build_given\":%s", pm, nm, bstr(x64[0]), bstr(x86[0]));
  emulation_one("native", g_self);
  if (x64[0]) emulation_one("x64", x64);
  if (x86[0]) emulation_one("x86", x86);
}

/* ------------------------------------------------------------------ scale */
static int cmp_d(const void *a, const void *b) { double x = *(const double *)a, y = *(const double *)b; return x < y ? -1 : x > y; }

static void latency_series(const char *name, int with_job, const wchar_t *exe, int n) {
  double *call = (double *)calloc((size_t)n, sizeof(double)), *total = (double *)calloc((size_t)n, sizeof(double));
  int ok = 0;
  HANDLE job = NULL;
  if (with_job) job = CreateJobObjectW(NULL, NULL);
  for (int i = 0; i < n; i++) {
    PROCESS_INFORMATION pi;
    DWORD err;
    double t0 = abs_ms();
    if (!spawn_exe(exe, L"--child-sleep 0", with_job ? CREATE_SUSPENDED : 0, &pi, &err)) continue;
    if (with_job) { AssignProcessToJobObject(job, pi.hProcess); ResumeThread(pi.hThread); }
    double c = abs_ms() - t0;
    WaitForSingleObject(pi.hProcess, 10000);
    double t = abs_ms() - t0;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    call[ok] = c;
    total[ok] = t;
    ok++;
  }
  if (job) CloseHandle(job);
  if (ok > 0) {
    qsort(call, (size_t)ok, sizeof(double), cmp_d);
    qsort(total, (size_t)ok, sizeof(double), cmp_d);
    emit(name, "\"n\":%d,\"create_ms\":{\"min\":%.1f,\"median\":%.1f,\"p90\":%.1f,\"max\":%.1f},\"until_exit_ms\":{\"min\":%.1f,\"median\":%.1f,\"p90\":%.1f,\"max\":%.1f}",
         ok, call[0], call[ok / 2], call[(ok * 9) / 10 >= ok ? ok - 1 : (ok * 9) / 10], call[ok - 1], total[0], total[ok / 2], total[(ok * 9) / 10 >= ok ? ok - 1 : (ok * 9) / 10], total[ok - 1]);
  } else {
    emit(name, "\"n\":0");
  }
  free(call);
  free(total);
}

static void probe_scale(void) {
  /* a copy of the program that has never run: the first start of a new file (Defender / SmartScreen-style assessment) */
  wchar_t fresh[MAX_PATH * 2];
  swprintf(fresh, MAX_PATH * 2, L"%ls\\fresh-copy.exe", g_tmp);
  if (CopyFileW(g_self, fresh, FALSE)) {
    double t[3];
    for (int i = 0; i < 3; i++) {
      PROCESS_INFORMATION pi;
      DWORD err;
      double t0 = abs_ms();
      if (spawn_exe(fresh, L"--child-sleep 0", 0, &pi, &err)) { WaitForSingleObject(pi.hProcess, 20000); t[i] = abs_ms() - t0; CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
      else t[i] = -1;
    }
    emit("first_start_of_a_new_executable", "\"first_ms\":%.1f,\"second_ms\":%.1f,\"third_ms\":%.1f", t[0], t[1], t[2]);
  }
  latency_series("spawn_latency_plain", 0, g_self, 100);
  latency_series("spawn_latency_suspended_assigned_to_job_resumed", 1, g_self, 100);
  size_t big = (size_t)512 << 20;
  char *mem = (char *)VirtualAlloc(NULL, big, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (mem) {
    for (size_t i = 0; i < big; i += 4096) mem[i] = 1;
    latency_series("spawn_latency_plain_512MiB_parent", 0, g_self, 50);
    VirtualFree(mem, 0, MEM_RELEASE);
  }

  /* many children alive at once */
  HANDLE job = CreateJobObjectW(NULL, NULL);
  const int cap = 400;
  HANDLE *hs = (HANDLE *)calloc((size_t)cap, sizeof(HANDLE));
  int n = 0;
  DWORD err = 0;
  double first = 0, mid = 0, t_all = abs_ms();
  for (; n < cap; n++) {
    PROCESS_INFORMATION pi;
    double t0 = abs_ms();
    if (!spawn_self(L"--child-sleep 60000", CREATE_SUSPENDED, NULL, &pi, &err)) break;
    AssignProcessToJobObject(job, pi.hProcess);
    ResumeThread(pi.hThread);
    double dt = abs_ms() - t0;
    if (n < 50) first += dt;
    if (n >= 200 && n < 250) mid += dt;
    hs[n] = pi.hProcess;
    CloseHandle(pi.hThread);
  }
  double spawn_phase = abs_ms() - t_all;
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION ba;
  QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &ba, sizeof ba, NULL);
  double tk = abs_ms();
  TerminateJobObject(job, 1);
  int gone = 0;
  for (int i = 0; i < n; i++) if (WaitForSingleObject(hs[i], 20000) == WAIT_OBJECT_0) gone++;
  double kill_ms = abs_ms() - tk;
  for (int i = 0; i < n; i++) CloseHandle(hs[i]);
  free(hs);
  CloseHandle(job);
  emit("concurrent_children", "\"created\":%d,\"stopped_by\":\"%s\",\"error\":%lu,\"active_processes_in_job\":%lu,\"first_50_total_ms\":%.1f,\"processes_200_to_250_total_ms\":%.1f,\"spawn_phase_ms\":%.0f,\"terminate_job_until_all_exited_ms\":%.0f,\"exited\":%d",
       n, n >= cap ? "limit_of_this_probe" : "error", (unsigned long)err, (unsigned long)ba.ActiveProcesses, first, mid, spawn_phase, kill_ms, gone);
}

/* ------------------------------------------------------------------ header and main */
static DWORD WINAPI watchdog_thread(LPVOID p) {
  (void)p;
  Sleep(300000);
  emit("_watchdog", "\"error\":\"probe exceeded 300 s and was stopped\"");
  ExitProcess(3);
  return 0;
}

static void header(void) {
  typedef LONG(NTAPI * PFN_RtlGetVersion)(OSVERSIONINFOW *);
  OSVERSIONINFOW v;
  memset(&v, 0, sizeof v);
  v.dwOSVersionInfoSize = sizeof v;
  PFN_RtlGetVersion rgv = (PFN_RtlGetVersion)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
  if (rgv) rgv(&v);
  HANDLE tok = NULL;
  TOKEN_ELEVATION el;
  DWORD n = 0;
  BOOL elevated = FALSE;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
    if (GetTokenInformation(tok, TokenElevation, &el, sizeof el, &n)) elevated = el.TokenIsElevated;
    CloseHandle(tok);
  }
  BOOL in_job = FALSE;
  IsProcessInJob(GetCurrentProcess(), NULL, &in_job);
  DWORD session = 0;
  ProcessIdToSessionId(GetCurrentProcessId(), &session);
  emit("_platform", "\"windows\":\"%lu.%lu.%lu\",\"elevated\":%s,\"in_job\":%s,\"console_window\":%s,\"has_console\":%s,\"session_id\":%lu",
       (unsigned long)v.dwMajorVersion, (unsigned long)v.dwMinorVersion, (unsigned long)v.dwBuildNumber, bstr(elevated), bstr(in_job),
       bstr(GetConsoleWindow() != NULL), bstr(parent_has_console()), (unsigned long)session);
}

int main(void) {
  int argc = 0;
  wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  init_paths();
  if (argc >= 4 && wcscmp(argv[1], L"--child-ctrl") == 0) return child_ctrl(argv[2], argv[3]);
  if (argc >= 3 && wcscmp(argv[1], L"--child-sleep") == 0) { Sleep((DWORD)_wtoi(argv[2])); return 0; }
  if (argc >= 2 && wcscmp(argv[1], L"--child-spin") == 0) { double end = abs_ms() + 60000; volatile unsigned long x = 0; while (abs_ms() < end) { for (int i = 0; i < 100000; i++) x++; } return 0; }
  if (argc >= 3 && wcscmp(argv[1], L"--child-crash") == 0) return child_crash(_wtoi(argv[2]));
  if (argc >= 4 && wcscmp(argv[1], L"--child-write") == 0) return child_write(argv[2], _wtoi(argv[3]));
  if (argc >= 3 && wcscmp(argv[1], L"--child-write-stdout") == 0) return child_write_stdout(_wtoi(argv[2]));
  if (argc >= 2 && wcscmp(argv[1], L"--child-read-stdin") == 0) return child_read_stdin();
  if (argc >= 6 && wcscmp(argv[1], L"--child-io") == 0) return child_io(argv[2], argv[3], _wtoi(argv[4]), _wtoi(argv[5]));
  if (argc >= 5 && wcscmp(argv[1], L"--child-io-log") == 0) return child_io_log(argv[2], _wtoi(argv[3]), argv[4]);
  if (argc >= 3 && wcscmp(argv[1], L"--child-spawn-try") == 0) return child_spawn_try(argv[2]);
  if (argc >= 5 && wcscmp(argv[1], L"--sender") == 0) return child_sender(argv[2], (DWORD)_wtoi(argv[3]), argv[4]);
  if (argc >= 4 && wcscmp(argv[1], L"--child-debugger") == 0) return child_debugger(argv[2], _wtoi(argv[3]));
  if (argc >= 2 && wcscmp(argv[1], L"--child-thread-spawner") == 0) return child_thread_spawner();
  if (argc >= 4 && wcscmp(argv[1], L"--child-window") == 0) return child_window(argv[2], argv[3]);
  if (argc >= 5 && wcscmp(argv[1], L"--child-ac") == 0) return child_ac(argv[2], (DWORD)_wtoi(argv[3]), _wtoi(argv[4]));
  if (argc >= 3 && wcscmp(argv[1], L"--child-arch") == 0) return child_arch(argv[2]);
  if (argc >= 3 && wcscmp(argv[1], L"--child-alloc") == 0) return child_alloc(_wtoi(argv[2]));

  CreateThread(NULL, 0, watchdog_thread, NULL, 0, NULL);
  const wchar_t *which = argc >= 2 ? argv[1] : L"all";
  int all = wcscmp(which, L"all") == 0;
  header();
  if (all || wcscmp(which, L"ctrl") == 0) probe_ctrl();
  if (all || wcscmp(which, L"conpty") == 0) probe_conpty();
  if (all || wcscmp(which, L"parent") == 0) probe_parent();
  if (all || wcscmp(which, L"wait") == 0) probe_wait();
  if (all || wcscmp(which, L"rate") == 0) probe_rate();
  if (all || wcscmp(which, L"mitigation") == 0) probe_mitigation();
  if (all || wcscmp(which, L"debug") == 0) probe_debug();
  if (all || wcscmp(which, L"silo") == 0) probe_silo();
  if (all || wcscmp(which, L"period") == 0) probe_period();
  if (all || wcscmp(which, L"iorate") == 0) probe_iorate();
  if (all || wcscmp(which, L"pipes") == 0) probe_pipes();
  if (all || wcscmp(which, L"pidreuse") == 0) probe_pidreuse();
  if (all || wcscmp(which, L"suspend") == 0) probe_suspend();
  if (all || wcscmp(which, L"wmclose") == 0) probe_wmclose();
  if (all || wcscmp(which, L"appcontainer") == 0) probe_appcontainer();
  if (wcscmp(which, L"emulation") == 0) probe_emulation();
  if (all || wcscmp(which, L"scale") == 0) probe_scale();
  return 0;
}
