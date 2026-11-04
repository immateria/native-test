/*
 * Windows process-supervision exploration (C, MSVC or MinGW). Records JSON lines, never asserts.
 * Covers what the Job-object kit does not: console control events (the only graceful stop for console
 * programs), ConPTY, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, WaitForMultipleObjects limits and a job handle's
 * signaled state, registered waits at scale, job IO/network rate control, the child-process policy, crash
 * timing with and without a debugger, the debugger as a "die with my parent" mechanism, and silo creation.
 *
 * Build (from a VS developer prompt):  cl /nologo /O1 /Fe:proc_explore.exe proc_explore.c user32.lib advapi32.lib
 * Run:  proc_explore.exe [ctrl|conpty|parent|wait|rate|mitigation|debug|silo|all]
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

static int child_crash(int nogpfault) {
  if (nogpfault) SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
  volatile int *p = NULL;
  *p = 1;
  return 0;
}

/* a debugger that owns one sleeping child; used to test "debuggee dies with its debugger" */
static int child_debugger(const wchar_t *logpath, int kill_on_exit) {
  HANDLE log = open_log(logpath);
  if (!kill_on_exit) DebugSetProcessKillOnExit(FALSE);
  PROCESS_INFORMATION pi;
  DWORD err;
  if (!spawn_self(L"--child-sleep 60000", DEBUG_ONLY_THIS_PROCESS, NULL, &pi, &err)) {
    log_to(log, "ready spawn_failed=%lu\n", (unsigned long)err);
    return 1;
  }
  log_to(log, "ready child=%lu\n", (unsigned long)pi.dwProcessId);
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
  double t_exit = abs_ms();
  char evs[512];
  int saw;
  int n = events_text(log, t_send, evs, sizeof evs, &saw);
  emit(c->name,
       "\"parent_has_console\":%s,\"child\":\"%s\",\"send\":\"%s\",\"send_result\":\"%s\",\"events_received\":%d,\"events\":\"%s\","
       "\"child_exited_within_2500ms\":%s,\"child_exit_code\":\"0x%08lX\",\"ms_to_exit\":%.0f",
       bstr(parent_has_console()), info, c->send, send_result, n, evs, bstr(exited), (unsigned long)(exited ? code : 0),
       exited ? t_exit - t_send : -1.0);
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
  double t_exit = abs_ms();
  char evs[512];
  int saw;
  int n = events_text(log, t_send, evs, sizeof evs, &saw);
  emit(name,
       "\"child\":\"%s\",\"action\":\"%s\",\"action_result\":\"%s\",\"close_returned\":%s,\"close_ms\":%.0f,\"events_received\":%d,\"events\":\"%s\","
       "\"child_exited\":%s,\"child_exit_code\":\"0x%08lX\",\"ms_to_exit\":%.0f",
       info, action, what, bstr(close_returned), close_ms, n, evs, bstr(exited), (unsigned long)(exited ? code : 0), exited ? t_exit - t_send : -1.0);
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
    DWORD reported = 0;
    if (h) {
      LPPROC_THREAD_ATTRIBUTE_LIST a2 = make_attrs(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &h, sizeof(HANDLE));
      PROCESS_INFORMATION x;
      spawned = a2 && spawn_self(L"--child-sleep 2000", 0, a2, &x, &se);
      if (!a2) se = GetLastError();
      if (spawned) { reported = parent_pid_of(x.dwProcessId); kill_close(&x); }
      if (a2) DeleteProcThreadAttributeList(a2);
      CloseHandle(h);
    }
    emit(nm, "\"present\":true,\"OpenProcess_PROCESS_CREATE_PROCESS_ok\":%s,\"OpenProcess_err\":%lu,\"spawn_with_this_parent_ok\":%s,\"spawn_err\":%lu,\"child_reports_that_parent\":%s",
         bstr(h != NULL), (unsigned long)oe, bstr(spawned), (unsigned long)se, bstr(spawned && reported == pids[i]));
  }
  CloseHandle(job);
}

/* ------------------------------------------------------------------ waits */
static volatile LONG g_fired;
static VOID CALLBACK wait_cb(PVOID ctx, BOOLEAN timed_out) { (void)ctx; if (!timed_out) InterlockedIncrement(&g_fired); }

static double ft_ms(FILETIME f) { ULARGE_INTEGER u; u.LowPart = f.dwLowDateTime; u.HighPart = f.dwHighDateTime; return (double)u.QuadPart / 10000.0; }

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
  double max_lat = 0;
  int n = 8;
  while (n > 0) {
    DWORD w = WaitForMultipleObjects(n, hs, FALSE, 5000);
    double woke = abs_ms();
    if (w >= WAIT_OBJECT_0 + n) { sl += (size_t)snprintf(seq + sl, sizeof seq - sl, "timeout"); break; }
    int k = (int)(w - WAIT_OBJECT_0);
    FILETIME c, x, kt, ut;
    GetProcessTimes(hs[k], &c, &x, &kt, &ut);
    double lat = woke - ft_ms(x);
    if (lat > max_lat) max_lat = lat;
    sl += (size_t)snprintf(seq + sl, sizeof seq - sl, "%s%d", sl ? "," : "", orig[k]);
    hs[k] = hs[n - 1]; orig[k] = orig[n - 1];
    n--;
  }
  emit("wait_any_over_eight_processes", "\"exit_order_by_start_index\":\"%s\",\"expected\":\"7,6,5,4,3,2,1,0\",\"max_ms_between_process_exit_time_and_wakeup\":%.1f", seq, max_lat);
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
  emit("job_handle_signaled_at_time_limit",
       "\"post_at_end_of_job_signaled_ms\":%.0f,\"post_at_end_of_job_child_alive\":%s,\"terminate_at_end_of_job_signaled_ms\":%.0f,\"terminate_at_end_of_job_child_alive\":%s,\"note\":\"-1 = never signaled within the wait\"",
       sig[0], bstr(alive0), sig[1], bstr(alive1));
  for (int i = 0; i < 2; i++) { kill_close(&jp[i]); CloseHandle(jobs[i]); }
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
      DWORD qr = queryio ? queryio(job, NULL, &blocks, &count) : 0xFFFFFFFF;
      emit(i == 0 ? "io_rate_control_enable" : "io_rate_control_enable_standalone_volume",
           "\"set_return\":%lu,\"last_error\":%lu,\"query_return\":%lu,\"query_block_count\":%lu,\"first_block_max_iops\":%lld",
           (unsigned long)ret, (unsigned long)le, (unsigned long)qr, (unsigned long)count, (long long)(blocks && count ? blocks[0].MaxIops : -1));
    }
  }
  CloseHandle(job);
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
  emit(name, "\"debugger_calls_DebugSetProcessKillOnExit_FALSE\":%s,\"debuggee_alive_before\":%s,\"debuggee_died_after_debugger_was_terminated\":%s,\"ms\":%.0f,\"debuggee_exit_code\":\"0x%08lX\"",
       bstr(!kill_on_exit), bstr(alive_before), bstr(died), died ? dt : -1.0, (unsigned long)(died ? code : 0));
  if (ch) { TerminateProcess(ch, 1); CloseHandle(ch); }
  kill_close(&helper);
}

static void probe_debug(void) {
  crash_case("crash_without_debugger_default_error_mode", 0);
  crash_case("crash_without_debugger_SEM_NOGPFAULTERRORBOX", 1);
  debug_crash_case();
  debugger_dies_case("debuggee_when_its_debugger_is_terminated_default", 1);
  debugger_dies_case("debuggee_when_its_debugger_is_terminated_kill_on_exit_false", 0);
}

/* ------------------------------------------------------------------ silo */
static void probe_silo(void) {
  HMODULE nt = GetModuleHandleW(L"ntdll.dll");
  typedef LONG(NTAPI * PFN_NtSetInformationJobObject)(HANDLE, int, PVOID, ULONG);
  PFN_NtSetInformationJobObject f = (PFN_NtSetInformationJobObject)(void *)GetProcAddress(nt, "NtSetInformationJobObject");
  if (!f) { emit("silo_create", "\"unsupported\":\"NtSetInformationJobObject not found\""); return; }
  HANDLE job = CreateJobObjectW(NULL, NULL);
  LONG st = f(job, 35 /* JobObjectCreateSilo */, NULL, 0);
  emit("silo_create_application_silo", "\"ntstatus\":\"0x%08lX\",\"note\":\"0 = created; 0xC0000022 = access denied; 0xC0000003 = information class not valid\"", (unsigned long)st);
  CloseHandle(job);
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
  return 0;
}
