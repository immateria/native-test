/*
 * Windows process-supervision exploration (C, MSVC or MinGW). Records JSON lines, never asserts.
 * Covers what the Job-object kit does not: console control events (the only graceful stop for console
 * programs), ConPTY, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, WaitForMultipleObjects limits and a job handle's
 * signaled state, registered waits at scale, job IO/network rate control, the child-process policy, crash
 * timing with and without a debugger, the debugger as a "die with my parent" mechanism, and silo creation.
 *
 * Build (from a VS developer prompt):  cl /nologo /O1 /Fe:proc_explore.exe proc_explore.c user32.lib advapi32.lib
 * Run:  proc_explore.exe [ctrl|conpty|parent|wait|rate|mitigation|debug|silo|period|iorate|all]
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
#include <shellapi.h>
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
    if (!ok) return 3;
    if (mode[0] == L'f') FlushFileBuffers(h); /* buffered overwrite + flush after each write */
  }
}

typedef struct { const char *name; const wchar_t *mode; int size, flags; LONG64 max_iops, max_bw; } io_case_t;

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
    {"iorate_4k_append_writethrough_unbuffered", L"a", 4096, 3, 20, 0},
    {"iorate_4k_overwrite_writethrough_unbuffered", L"o", 4096, 3, 20, 0},
    {"iorate_4k_overwrite_unbuffered", L"o", 4096, 1, 20, 0},
    {"iorate_4k_append_unbuffered", L"a", 4096, 1, 20, 0},
    {"iorate_4k_overwrite_buffered_flush_each", L"f", 4096, 0, 20, 0},
    {"iorate_4k_read_unbuffered", L"r", 4096, 1, 20, 0},
    {"iorate_64k_overwrite_unbuffered", L"o", 65536, 1, 20, 0},
    {"iorate_4k_overwrite_unbuffered_limit_40", L"o", 4096, 1, 40, 0},
    {"iorate_64k_overwrite_unbuffered_bandwidth_1MB", L"o", 65536, 1, 0, 1000000},
  };
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
    const io_case_t *c = &cases[i];
    const wchar_t *path = c->mode[0] == L'a' ? fapp : fpre;
    char lim[512], free_[512];
    io_run(c, 1, setio, path, 5000, lim, sizeof lim);
    io_run(c, 0, setio, path, 1500, free_, sizeof free_);
    emit(c->name, "\"max_iops\":%lld,\"max_bandwidth\":%lld,\"io_size\":%d,\"limited\":{%s},\"unlimited\":{%s}", (long long)c->max_iops, (long long)c->max_bw, c->size, lim, free_);
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
  emit("_platform", "\"windows\":\"%lu.%lu.%lu\",\"elevated\":%s,\"in_job\":%s,\"console_window\":%s,\"has_console\":%s",
       (unsigned long)v.dwMajorVersion, (unsigned long)v.dwMinorVersion, (unsigned long)v.dwBuildNumber, bstr(elevated), bstr(in_job),
       bstr(GetConsoleWindow() != NULL), bstr(parent_has_console()));
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
  if (argc >= 6 && wcscmp(argv[1], L"--child-io") == 0) return child_io(argv[2], argv[3], _wtoi(argv[4]), _wtoi(argv[5]));
  if (argc >= 3 && wcscmp(argv[1], L"--child-spawn-try") == 0) return child_spawn_try(argv[2]);
  if (argc >= 5 && wcscmp(argv[1], L"--sender") == 0) return child_sender(argv[2], (DWORD)_wtoi(argv[3]), argv[4]);
  if (argc >= 4 && wcscmp(argv[1], L"--child-debugger") == 0) return child_debugger(argv[2], _wtoi(argv[3]));

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
  return 0;
}
