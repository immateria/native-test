/*
 * More Windows supervision probes (C; MSVC or MinGW). Records JSON lines, never asserts.
 *
 *   priority   job priority class and affinity on a child created into the job, on a suspended child assigned
 *              afterwards (read before it resumes), and on a member when the limit is set on a populated job; the
 *              scheduling class setter; and a deliberately shifted structure (what the Crystal union bug passed) to
 *              confirm that Windows then installs no limit at all
 *   desktop    the token, window station and desktop this process runs with (SIDs, DACLs as SDDL, which access
 *              rights open), pipe creation plus a redirected CreateProcess the way .NET does it, and children started
 *              with CREATE_NEW_CONSOLE / CREATE_NO_WINDOW / DETACHED_PROCESS
 *   services   an own-process test service (LocalSystem, session 0) with a worker child: stop, stop with a
 *              kill-on-close job, a stop handler that never returns, crash / exit / failed stop under recovery
 *              actions, WER LocalDumps off / mini / full, and putting a session-0 process into a session-2 job
 *   exitproc   ExitProcess while a terminated thread held what DLL_PROCESS_DETACH needs (detach_dll.dll)
 *
 * Build (VS prompt): cl /nologo /O1 /W3 win_more.c ; cl /nologo /O1 /W3 /LD detach_dll.c
 * Run:   win_more.exe priority|desktop|services|exitproc
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
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

#ifndef PROC_THREAD_ATTRIBUTE_JOB_LIST
#define PROC_THREAD_ATTRIBUTE_JOB_LIST 0x0002000D
#endif

#define PROBE "win_more"

/* ------------------------------------------------------------------ helpers */
static double abs_ms(void) {
  FILETIME ft;
  GetSystemTimePreciseAsFileTime(&ft);
  ULARGE_INTEGER u;
  u.LowPart = ft.dwLowDateTime;
  u.HighPart = ft.dwHighDateTime;
  return (double)u.QuadPart / 10000.0;
}

static double ft_ms(FILETIME f) { ULARGE_INTEGER u; u.LowPart = f.dwLowDateTime; u.HighPart = f.dwHighDateTime; return (double)u.QuadPart / 10000.0; }

/* kernel exit time of an exited process minus t_ref; -1 if it has not exited */
static double exit_after(HANDLE h, double t_ref) {
  FILETIME c, x, k, u;
  if (!h || WaitForSingleObject(h, 0) != WAIT_OBJECT_0 || !GetProcessTimes(h, &c, &x, &k, &u)) return -1;
  return ft_ms(x) - t_ref;
}

static void emit(const char *kase, const char *fmt, ...) {
  static char body[16384];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(body, sizeof body, fmt, ap);
  va_end(ap);
  printf("{\"probe\":\"%s\",\"case\":\"%s\",%s}\n", PROBE, kase, body);
  fflush(stdout);
}

static const char *bstr(int b) { return b ? "true" : "false"; }

/* JSON-safe copy: backslashes become '/', quotes and control characters become ' ' */
static void jsafe(char *s) {
  for (; *s; s++) {
    if (*s == '\\') *s = '/';
    else if (*s == '"' || (unsigned char)*s < 0x20) *s = ' ';
  }
}

static void wtext(const wchar_t *w, char *out, int n) {
  if (!w) { out[0] = 0; return; }
  WideCharToMultiByte(CP_UTF8, 0, w, -1, out, n, NULL, NULL);
  jsafe(out);
}

static wchar_t g_self[MAX_PATH * 2];
static wchar_t g_tmp[MAX_PATH * 2];

static void init_paths(void) {
  GetModuleFileNameW(NULL, g_self, (DWORD)(sizeof g_self / sizeof g_self[0]));
  wchar_t base[MAX_PATH * 2];
  GetTempPathW((DWORD)(sizeof base / sizeof base[0]), base);
  swprintf(g_tmp, sizeof g_tmp / sizeof g_tmp[0], L"%lswin-more-%lu", base, (unsigned long)GetCurrentProcessId());
  CreateDirectoryW(g_tmp, NULL);
}

static int read_text(const wchar_t *path, char *buf, size_t cap) {
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) { buf[0] = 0; return -1; }
  DWORD got = 0;
  ReadFile(h, buf, (DWORD)(cap - 1), &got, NULL);
  CloseHandle(h);
  buf[got] = 0;
  return (int)got;
}

static HANDLE open_log(const wchar_t *path) {
  return CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

static void log_to(HANDLE h, const char *fmt, ...) {
  char b[2048];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(b, sizeof b, fmt, ap);
  va_end(ap);
  DWORD w;
  if (h && h != INVALID_HANDLE_VALUE && n > 0) WriteFile(h, b, (DWORD)n, &w, NULL);
}

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

static void kill_close(PROCESS_INFORMATION *pi) {
  if (pi->hProcess) { TerminateProcess(pi->hProcess, 1); WaitForSingleObject(pi->hProcess, 2000); CloseHandle(pi->hProcess); }
  if (pi->hThread) CloseHandle(pi->hThread);
  memset(pi, 0, sizeof *pi);
}

/* enable a privilege in the process token; returns 1 if it is now enabled, 0 if not held, -1 on error */
static int enable_privilege(const wchar_t *name) {
  HANDLE tok;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return -1;
  TOKEN_PRIVILEGES tp;
  tp.PrivilegeCount = 1;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  if (!LookupPrivilegeValueW(NULL, name, &tp.Privileges[0].Luid)) { CloseHandle(tok); return -1; }
  BOOL ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof tp, NULL, NULL);
  DWORD e = GetLastError();
  CloseHandle(tok);
  return ok && e == ERROR_SUCCESS ? 1 : 0;
}

static int is_elevated(void) {
  HANDLE tok;
  TOKEN_ELEVATION el;
  DWORD n = 0;
  int r = 0;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
    if (GetTokenInformation(tok, TokenElevation, &el, sizeof el, &n)) r = el.TokenIsElevated != 0;
    CloseHandle(tok);
  }
  return r;
}

/* ================================================================== priority */
static const struct { const char *name; DWORD v; } k_classes[] = {
  {"idle", IDLE_PRIORITY_CLASS}, {"below_normal", BELOW_NORMAL_PRIORITY_CLASS}, {"normal", NORMAL_PRIORITY_CLASS},
  {"above_normal", ABOVE_NORMAL_PRIORITY_CLASS}, {"high", HIGH_PRIORITY_CLASS}};

static BOOL set_basic(HANDLE job, DWORD flags, DWORD prio, ULONG_PTR affinity, DWORD sched, DWORD *err) {
  JOBOBJECT_BASIC_LIMIT_INFORMATION b;
  memset(&b, 0, sizeof b);
  b.LimitFlags = flags;
  b.PriorityClass = prio;
  b.Affinity = affinity;
  b.SchedulingClass = sched;
  BOOL ok = SetInformationJobObject(job, JobObjectBasicLimitInformation, &b, sizeof b);
  *err = ok ? 0 : GetLastError();
  return ok;
}

static void query_basic(HANDLE job, char *out, size_t n) {
  JOBOBJECT_BASIC_LIMIT_INFORMATION b;
  memset(&b, 0, sizeof b);
  if (QueryInformationJobObject(job, JobObjectBasicLimitInformation, &b, sizeof b, NULL))
    snprintf(out, n, "{\"flags\":\"0x%lx\",\"priority_class\":\"0x%lx\",\"affinity\":\"0x%llx\",\"scheduling_class\":%lu}", (unsigned long)b.LimitFlags,
             (unsigned long)b.PriorityClass, (unsigned long long)b.Affinity, (unsigned long)b.SchedulingClass);
  else snprintf(out, n, "{\"query_error\":%lu}", (unsigned long)GetLastError());
}

static ULONG_PTR proc_affinity(HANDLE h) {
  DWORD_PTR pm = 0, sm = 0;
  GetProcessAffinityMask(h, &pm, &sm);
  return (ULONG_PTR)pm;
}

enum { P_CREATED_IN_JOB, P_ASSIGNED_SUSPENDED, P_POPULATED_UPDATE };

static void prio_case(int how, const char *cname, DWORD cls, ULONG_PTR aff) {
  static const char *hows[] = {"created_in_job", "assigned_after_creation", "limit_set_on_populated_job"};
  char kase[128];
  snprintf(kase, sizeof kase, "priority_%s_%s", hows[how], cname);
  HANDLE job = CreateJobObjectW(NULL, NULL);
  DWORD flags = JOB_OBJECT_LIMIT_PRIORITY_CLASS | (aff ? JOB_OBJECT_LIMIT_AFFINITY : 0);
  DWORD set_err = 0, assign_err = 0, e = 0;
  BOOL set_ok = TRUE, assign_ok = TRUE;
  PROCESS_INFORMATION pi;
  memset(&pi, 0, sizeof pi);
  DWORD c0 = 0, c1 = 0, c2 = 0, c3 = 0;
  ULONG_PTR a0 = 0, a1 = 0, a2 = 0;
  if (how != P_POPULATED_UPDATE) set_ok = set_basic(job, flags, cls, aff, 0, &set_err);
  if (how == P_CREATED_IN_JOB) {
    SIZE_T sz = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &sz);
    LPPROC_THREAD_ATTRIBUTE_LIST al = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sz);
    InitializeProcThreadAttributeList(al, 1, 0, &sz);
    UpdateProcThreadAttribute(al, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &job, sizeof job, NULL, NULL);
    if (!spawn_self(L"--child-sleep 3000", CREATE_SUSPENDED, al, &pi, &e)) { emit(kase, "\"spawn_error\":%lu", (unsigned long)e); CloseHandle(job); return; }
    DeleteProcThreadAttributeList(al);
    HeapFree(GetProcessHeap(), 0, al);
    c1 = GetPriorityClass(pi.hProcess); a1 = proc_affinity(pi.hProcess);
    ResumeThread(pi.hThread);
    Sleep(100);
    c2 = GetPriorityClass(pi.hProcess); a2 = proc_affinity(pi.hProcess);
  } else if (how == P_ASSIGNED_SUSPENDED) {
    if (!spawn_self(L"--child-sleep 3000", CREATE_SUSPENDED, NULL, &pi, &e)) { emit(kase, "\"spawn_error\":%lu", (unsigned long)e); CloseHandle(job); return; }
    c0 = GetPriorityClass(pi.hProcess); a0 = proc_affinity(pi.hProcess);
    assign_ok = AssignProcessToJobObject(job, pi.hProcess);
    assign_err = assign_ok ? 0 : GetLastError();
    c1 = GetPriorityClass(pi.hProcess); a1 = proc_affinity(pi.hProcess); /* still suspended */
    ResumeThread(pi.hThread);
    Sleep(100);
    c2 = GetPriorityClass(pi.hProcess); a2 = proc_affinity(pi.hProcess);
  } else {
    if (!spawn_self(L"--child-sleep 3000", CREATE_SUSPENDED, NULL, &pi, &e)) { emit(kase, "\"spawn_error\":%lu", (unsigned long)e); CloseHandle(job); return; }
    assign_ok = AssignProcessToJobObject(job, pi.hProcess);
    assign_err = assign_ok ? 0 : GetLastError();
    ResumeThread(pi.hThread);
    Sleep(50);
    c0 = GetPriorityClass(pi.hProcess); a0 = proc_affinity(pi.hProcess);
    set_ok = set_basic(job, flags, cls, aff, 0, &set_err);
    c1 = GetPriorityClass(pi.hProcess); a1 = proc_affinity(pi.hProcess); /* immediately after the set */
    Sleep(100);
    c2 = GetPriorityClass(pi.hProcess); a2 = proc_affinity(pi.hProcess);
  }
  Sleep(1000);
  c3 = GetPriorityClass(pi.hProcess);
  char inst[256];
  query_basic(job, inst, sizeof inst);
  emit(kase,
       "\"requested_class\":\"0x%lx\",\"requested_affinity\":\"0x%llx\",\"set_ok\":%s,\"set_error\":%lu,\"assign_ok\":%s,\"assign_error\":%lu,\"installed\":%s,"
       "\"child_class\":{\"before\":\"0x%lx\",\"at_assignment_or_set\":\"0x%lx\",\"100ms_later\":\"0x%lx\",\"1.1s_later\":\"0x%lx\"},"
       "\"child_affinity\":{\"before\":\"0x%llx\",\"at_assignment_or_set\":\"0x%llx\",\"100ms_later\":\"0x%llx\"}",
       (unsigned long)cls, (unsigned long long)aff, bstr(set_ok), (unsigned long)set_err, bstr(assign_ok), (unsigned long)assign_err, inst,
       (unsigned long)c0, (unsigned long)c1, (unsigned long)c2, (unsigned long)c3, (unsigned long long)a0, (unsigned long long)a1, (unsigned long long)a2);
  kill_close(&pi);
  CloseHandle(job);
}

/* What the Crystal union bug sent: the struct starts 8 bytes into the buffer (after the union's type tag), but the
 * length passed is still sizeof(struct). Compare with the same request passed correctly. */
static void shifted_struct_demo(const char *phase) {
  union { ULONGLONG align; unsigned char b[8 + sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION)]; } buf;
  memset(&buf, 0, sizeof buf);
  *(INT32 *)buf.b = 427; /* a plausible type id */
  JOBOBJECT_BASIC_LIMIT_INFORMATION *shifted = (JOBOBJECT_BASIC_LIMIT_INFORMATION *)(buf.b + 8);
  shifted->LimitFlags = JOB_OBJECT_LIMIT_PRIORITY_CLASS;
  shifted->PriorityClass = HIGH_PRIORITY_CLASS;
  HANDLE j1 = CreateJobObjectW(NULL, NULL), j2 = CreateJobObjectW(NULL, NULL);
  BOOL ok1 = SetInformationJobObject(j1, JobObjectBasicLimitInformation, buf.b, sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION));
  DWORD e1 = ok1 ? 0 : GetLastError();
  BOOL ok2 = SetInformationJobObject(j2, JobObjectBasicLimitInformation, shifted, sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION));
  DWORD e2 = ok2 ? 0 : GetLastError();
  char i1[256], i2[256];
  query_basic(j1, i1, sizeof i1);
  query_basic(j2, i2, sizeof i2);
  char kase[96];
  snprintf(kase, sizeof kase, "priority_high_struct_shifted_by_8_bytes_%s", phase);
  emit(kase, "\"shifted\":{\"set_ok\":%s,\"set_error\":%lu,\"installed\":%s},\"correct\":{\"set_ok\":%s,\"set_error\":%lu,\"installed\":%s}",
       bstr(ok1), (unsigned long)e1, i1, bstr(ok2), (unsigned long)e2, i2);
  CloseHandle(j1);
  CloseHandle(j2);
}

static void probe_priority(void) {
  DWORD own = GetPriorityClass(GetCurrentProcess());
  DWORD_PTR pm = 0, sm = 0;
  GetProcessAffinityMask(GetCurrentProcess(), &pm, &sm);
  ULONG_PTR aff = 0;
  int bits = 0;
  for (int i = 0; i < (int)(sizeof(DWORD_PTR) * 8); i++) if (pm & ((DWORD_PTR)1 << i)) { if (!aff) aff = (ULONG_PTR)1 << i; bits++; }
  if (bits < 2) aff = 0; /* one CPU: an affinity limit would change nothing */
  emit("priority_context", "\"own_class\":\"0x%lx\",\"process_affinity\":\"0x%llx\",\"system_affinity\":\"0x%llx\",\"affinity_requested_in_cases\":\"0x%llx\",\"elevated\":%s",
       (unsigned long)own, (unsigned long long)pm, (unsigned long long)sm, (unsigned long long)aff, bstr(is_elevated()));
  shifted_struct_demo("privilege_not_enabled");
  int en = enable_privilege(L"SeIncreaseBasePriorityPrivilege");
  emit("priority_enable_SeIncreaseBasePriorityPrivilege", "\"enabled\":%d", en);
  if (en == 1) shifted_struct_demo("privilege_enabled");
  for (size_t i = 0; i < sizeof k_classes / sizeof k_classes[0]; i++)
    for (int how = 0; how < 3; how++) prio_case(how, k_classes[i].name, k_classes[i].v, aff);
  /* the scheduling class setter: 5 is the documented default, above 5 needs SeIncreaseBasePriorityPrivilege */
  int scheds[] = {0, 5, 9};
  for (int i = 0; i < 3; i++) {
    HANDLE j = CreateJobObjectW(NULL, NULL);
    DWORD e = 0;
    BOOL ok = set_basic(j, JOB_OBJECT_LIMIT_SCHEDULING_CLASS, 0, 0, (DWORD)scheds[i], &e);
    char inst[256];
    query_basic(j, inst, sizeof inst);
    char kase[64];
    snprintf(kase, sizeof kase, "scheduling_class_%d", scheds[i]);
    emit(kase, "\"set_ok\":%s,\"set_error\":%lu,\"installed\":%s", bstr(ok), (unsigned long)e, inst);
    CloseHandle(j);
  }
}

/* ================================================================== desktop */
static void sid_text(PSID sid, char *out, size_t n) {
  LPSTR s = NULL;
  if (sid && ConvertSidToStringSidA(sid, &s)) { snprintf(out, n, "%s", s); LocalFree(s); }
  else snprintf(out, n, "?");
}

static void sd_text(PSECURITY_DESCRIPTOR sd, SECURITY_INFORMATION si, char *out, size_t n) {
  LPSTR s = NULL;
  ULONG l = 0;
  if (ConvertSecurityDescriptorToStringSecurityDescriptorA(sd, SDDL_REVISION_1, si, &s, &l)) { snprintf(out, n, "%s", s); LocalFree(s); }
  else snprintf(out, n, "error %lu", (unsigned long)GetLastError());
  jsafe(out);
}

static void desktop_token(void) {
  HANDLE tok;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) { emit("token", "\"open_error\":%lu", (unsigned long)GetLastError()); return; }
  static BYTE buf[16384];
  DWORD n = 0;
  char user[200] = "?", owner[200] = "?", integ[200] = "?", dacl[2048] = "?", groups[6000] = "", logon[200] = "none";
  if (GetTokenInformation(tok, TokenUser, buf, sizeof buf, &n)) sid_text(((TOKEN_USER *)buf)->User.Sid, user, sizeof user);
  if (GetTokenInformation(tok, TokenOwner, buf, sizeof buf, &n)) sid_text(((TOKEN_OWNER *)buf)->Owner, owner, sizeof owner);
  if (GetTokenInformation(tok, TokenIntegrityLevel, buf, sizeof buf, &n)) sid_text(((TOKEN_MANDATORY_LABEL *)buf)->Label.Sid, integ, sizeof integ);
  if (GetTokenInformation(tok, TokenDefaultDacl, buf, sizeof buf, &n)) {
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, ((TOKEN_DEFAULT_DACL *)buf)->DefaultDacl, FALSE);
    sd_text(&sd, DACL_SECURITY_INFORMATION, dacl, sizeof dacl);
  }
  int ngroups = 0;
  if (GetTokenInformation(tok, TokenGroups, buf, sizeof buf, &n)) {
    TOKEN_GROUPS *g = (TOKEN_GROUPS *)buf;
    size_t l = 0;
    ngroups = (int)g->GroupCount;
    for (DWORD i = 0; i < g->GroupCount && l < sizeof groups - 120; i++) {
      char s[200];
      sid_text(g->Groups[i].Sid, s, sizeof s);
      if ((g->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID) snprintf(logon, sizeof logon, "%s", s);
      l += (size_t)snprintf(groups + l, sizeof groups - l, "%s%s=0x%lx", i ? "," : "", s, (unsigned long)g->Groups[i].Attributes);
    }
  }
  DWORD restricted = 0;
  if (GetTokenInformation(tok, TokenRestrictedSids, buf, sizeof buf, &n)) restricted = ((TOKEN_GROUPS *)buf)->GroupCount;
  TOKEN_ELEVATION_TYPE et = TokenElevationTypeDefault;
  GetTokenInformation(tok, TokenElevationType, &et, sizeof et, &n);
  TOKEN_LINKED_TOKEN lt;
  BOOL lok = GetTokenInformation(tok, TokenLinkedToken, &lt, sizeof lt, &n);
  DWORD lerr = lok ? 0 : GetLastError();
  if (lok) CloseHandle(lt.LinkedToken);
  DWORD sess = 0;
  ProcessIdToSessionId(GetCurrentProcessId(), &sess);
  emit("token", "\"elevated\":%s,\"elevation_type\":%d,\"linked_token_ok\":%s,\"linked_token_error\":%lu,\"session\":%lu,\"user\":\"%s\",\"owner\":\"%s\",\"integrity\":\"%s\",\"logon_sid\":\"%s\",\"restricted_sids\":%lu,\"default_dacl\":\"%s\",\"group_count\":%d,\"groups\":\"%s\"",
       bstr(is_elevated()), (int)et, bstr(lok), (unsigned long)lerr, (unsigned long)sess, user, owner, integ, logon, (unsigned long)restricted, dacl, ngroups, groups);
  CloseHandle(tok);
}

static void object_dacl(HANDLE h, char *out, size_t n) {
  static BYTE sd[16384];
  SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
  DWORD need = 0;
  if (GetUserObjectSecurity(h, &si, sd, sizeof sd, &need)) sd_text(sd, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, out, n);
  else snprintf(out, n, "error %lu", (unsigned long)GetLastError());
}

static void desktop_objects(void) {
  HWINSTA ws = GetProcessWindowStation();
  HDESK dk = GetThreadDesktop(GetCurrentThreadId());
  wchar_t wsn[256] = L"", dkn[256] = L"";
  DWORD n = 0;
  GetUserObjectInformationW(ws, UOI_NAME, wsn, sizeof wsn, &n);
  GetUserObjectInformationW(dk, UOI_NAME, dkn, sizeof dkn, &n);
  char wsa[256], dka[256];
  wtext(wsn, wsa, sizeof wsa);
  wtext(dkn, dka, sizeof dka);
  char wsd[4096], dsd[4096], wsd2[4096] = "", dsd2[4096] = "";
  object_dacl(ws, wsd, sizeof wsd);
  object_dacl(dk, dsd, sizeof dsd);
  HWINSTA ws2 = OpenWindowStationW(wsn, FALSE, READ_CONTROL);
  if (ws2) { object_dacl(ws2, wsd2, sizeof wsd2); CloseWindowStation(ws2); } else snprintf(wsd2, sizeof wsd2, "open error %lu", (unsigned long)GetLastError());
  HDESK dk2 = OpenDesktopW(dkn, 0, FALSE, READ_CONTROL);
  if (dk2) { object_dacl(dk2, dsd2, sizeof dsd2); CloseDesktop(dk2); } else snprintf(dsd2, sizeof dsd2, "open error %lu", (unsigned long)GetLastError());
  emit("window_station_and_desktop", "\"window_station\":\"%s\",\"desktop\":\"%s\",\"window_station_sd_own_handle\":\"%s\",\"desktop_sd_own_handle\":\"%s\",\"window_station_sd_reopened\":\"%s\",\"desktop_sd_reopened\":\"%s\"",
       wsa, dka, wsd, dsd, wsd2, dsd2);
  static const struct { const char *n; DWORD m; } wr[] = {
    {"ENUMDESKTOPS", 0x1}, {"READATTRIBUTES", 0x2}, {"ACCESSCLIPBOARD", 0x4}, {"CREATEDESKTOP", 0x8}, {"WRITEATTRIBUTES", 0x10},
    {"ACCESSGLOBALATOMS", 0x20}, {"EXITWINDOWS", 0x40}, {"ENUMERATE", 0x100}, {"READSCREEN", 0x200}, {"READ_CONTROL", READ_CONTROL}, {"WRITE_DAC", WRITE_DAC}, {"ALL_ACCESS", 0x37F}};
  static const struct { const char *n; DWORD m; } dr[] = {
    {"READOBJECTS", 0x1}, {"CREATEWINDOW", 0x2}, {"CREATEMENU", 0x4}, {"HOOKCONTROL", 0x8}, {"JOURNALRECORD", 0x10}, {"JOURNALPLAYBACK", 0x20},
    {"ENUMERATE", 0x40}, {"WRITEOBJECTS", 0x80}, {"SWITCHDESKTOP", 0x100}, {"READ_CONTROL", READ_CONTROL}, {"WRITE_DAC", WRITE_DAC}, {"GENERIC_ALL", GENERIC_ALL}};
  char wres[1024] = "", dres[1024] = "";
  size_t l = 0;
  for (size_t i = 0; i < sizeof wr / sizeof wr[0]; i++) {
    HWINSTA h = OpenWindowStationW(wsn, FALSE, wr[i].m);
    l += (size_t)snprintf(wres + l, sizeof wres - l, "%s\"%s\":%lu", i ? "," : "", wr[i].n, h ? 0UL : (unsigned long)GetLastError());
    if (h) CloseWindowStation(h);
  }
  l = 0;
  for (size_t i = 0; i < sizeof dr / sizeof dr[0]; i++) {
    HDESK h = OpenDesktopW(dkn, 0, FALSE, dr[i].m);
    l += (size_t)snprintf(dres + l, sizeof dres - l, "%s\"%s\":%lu", i ? "," : "", dr[i].n, h ? 0UL : (unsigned long)GetLastError());
    if (h) CloseDesktop(h);
  }
  emit("open_rights_error_codes", "\"note\":\"0 = opened\",\"window_station\":{%s},\"desktop\":{%s}", wres, dres);
}

static void desktop_pipe_spawn(void) {
  SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
  HANDLE r = NULL, w = NULL;
  BOOL pok = CreatePipe(&r, &w, &sa, 0);
  DWORD perr = pok ? 0 : GetLastError();
  char psd[2048] = "";
  if (pok) {
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD gr = GetSecurityInfo(r, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &sd);
    if (gr == ERROR_SUCCESS && sd) { sd_text(sd, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, psd, sizeof psd); LocalFree(sd); }
    else snprintf(psd, sizeof psd, "GetSecurityInfo error %lu", (unsigned long)gr);
  }
  /* .NET duplicates the parent's end as non-inheritable before CreateProcess */
  HANDLE r2 = NULL;
  BOOL dok = pok && DuplicateHandle(GetCurrentProcess(), r, GetCurrentProcess(), &r2, 0, FALSE, DUPLICATE_SAME_ACCESS);
  DWORD derr = dok ? 0 : GetLastError();
  if (r) CloseHandle(r);
  wchar_t sys[MAX_PATH], cmd[MAX_PATH * 2];
  GetSystemDirectoryW(sys, MAX_PATH);
  swprintf(cmd, MAX_PATH * 2, L"\"%ls\\cmd.exe\" /c ver", sys);
  STARTUPINFOW si;
  memset(&si, 0, sizeof si);
  si.cb = sizeof si;
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  si.hStdOutput = w;
  si.hStdError = w;
  PROCESS_INFORMATION pi;
  memset(&pi, 0, sizeof pi);
  BOOL cok = pok && CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi);
  DWORD cerr = cok ? 0 : GetLastError();
  if (w) CloseHandle(w);
  char out[512] = "";
  DWORD got = 0, code = 0;
  if (cok) {
    DWORD t = 0, k;
    while (t < sizeof out - 1 && ReadFile(r2, out + t, (DWORD)(sizeof out - 1 - t), &k, NULL) && k > 0) t += k;
    out[t] = 0;
    got = t;
    WaitForSingleObject(pi.hProcess, 5000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
  }
  if (r2) CloseHandle(r2);
  jsafe(out);
  emit("pipe_and_redirected_createprocess", "\"create_pipe_ok\":%s,\"create_pipe_error\":%lu,\"pipe_sd\":\"%s\",\"duplicate_ok\":%s,\"duplicate_error\":%lu,\"create_process_ok\":%s,\"create_process_error\":%lu,\"exit_code\":\"0x%08lx\",\"output_bytes\":%lu,\"output\":\"%s\"",
       bstr(pok), (unsigned long)perr, psd, bstr(dok), (unsigned long)derr, bstr(cok), (unsigned long)cerr, (unsigned long)code, (unsigned long)got, out);
}

static void desktop_flags(void) {
  static const struct { const char *n; DWORD f; } fl[] = {
    {"inherit_console", 0}, {"CREATE_NEW_CONSOLE", CREATE_NEW_CONSOLE}, {"CREATE_NO_WINDOW", CREATE_NO_WINDOW}, {"DETACHED_PROCESS", DETACHED_PROCESS}};
  wchar_t sys[MAX_PATH];
  GetSystemDirectoryW(sys, MAX_PATH);
  for (int target = 0; target < 2; target++) {
    char res[1024] = "";
    size_t l = 0;
    for (size_t i = 0; i < sizeof fl / sizeof fl[0]; i++) {
      wchar_t cmd[MAX_PATH * 3];
      if (target == 0) swprintf(cmd, MAX_PATH * 3, L"\"%ls\" --child-sleep 10", g_self);
      else swprintf(cmd, MAX_PATH * 3, L"\"%ls\\cmd.exe\" /c exit 3", sys);
      STARTUPINFOW si;
      memset(&si, 0, sizeof si);
      si.cb = sizeof si;
      PROCESS_INFORMATION pi;
      memset(&pi, 0, sizeof pi);
      BOOL ok = CreateProcessW(NULL, cmd, NULL, NULL, FALSE, fl[i].f, NULL, NULL, &si, &pi);
      DWORD err = ok ? 0 : GetLastError(), code = 0;
      int done = 0;
      if (ok) {
        done = WaitForSingleObject(pi.hProcess, 10000) == WAIT_OBJECT_0;
        GetExitCodeProcess(pi.hProcess, &code);
        if (!done) TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
      }
      l += (size_t)snprintf(res + l, sizeof res - l, "%s\"%s\":{\"create_error\":%lu,\"exited\":%s,\"exit_code\":\"0x%08lx\"}", i ? "," : "", fl[i].n, (unsigned long)err, bstr(done), (unsigned long)code);
    }
    emit(target == 0 ? "child_creation_flags_this_exe_links_user32" : "child_creation_flags_cmd_exe", "%s", res);
  }
}

static void probe_desktop(void) {
  DWORD pids[16];
  DWORD nproc = GetConsoleProcessList(pids, 16);
  HANDLE so = GetStdHandle(STD_OUTPUT_HANDLE);
  emit("console", "\"console_window\":%s,\"console_process_count\":%lu,\"stdout_file_type\":%lu", bstr(GetConsoleWindow() != NULL), (unsigned long)nproc, (unsigned long)GetFileType(so));
  desktop_token();
  desktop_objects();
  desktop_pipe_spawn();
  desktop_flags();
}

/* ================================================================== services */
#define SVC_CTL_CRASH 200
#define SVC_CTL_EXIT 201
#define SVC_CTL_FAILSTOP 202

static wchar_t g_svc_mode[32];
static SERVICE_STATUS_HANDLE g_ssh;
static HANDLE g_svc_stop, g_svc_log = INVALID_HANDLE_VALUE;
static DWORD g_svc_exit_code, g_svc_specific, g_svc_cp;

static void svc_status(DWORD state, DWORD wait_hint) {
  SERVICE_STATUS ss;
  memset(&ss, 0, sizeof ss);
  ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  ss.dwCurrentState = state;
  ss.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
  ss.dwWin32ExitCode = g_svc_exit_code;
  ss.dwServiceSpecificExitCode = g_svc_specific;
  ss.dwWaitHint = wait_hint;
  ss.dwCheckPoint = (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) ? ++g_svc_cp : 0;
  SetServiceStatus(g_ssh, &ss);
}

static DWORD WINAPI svc_handler(DWORD ctl, DWORD type, LPVOID data, LPVOID ctx) {
  (void)type; (void)data; (void)ctx;
  log_to(g_svc_log, "control=%lu t=%.3f\n", (unsigned long)ctl, abs_ms());
  switch (ctl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
      if (wcscmp(g_svc_mode, L"hang") == 0) { log_to(g_svc_log, "handler_hangs t=%.3f\n", abs_ms()); Sleep(INFINITE); }
      svc_status(SERVICE_STOP_PENDING, 5000);
      SetEvent(g_svc_stop);
      return NO_ERROR;
    case SVC_CTL_CRASH: {
      log_to(g_svc_log, "crash_at=%.3f\n", abs_ms());
      volatile int *p = NULL;
      *p = 1;
      return NO_ERROR;
    }
    case SVC_CTL_EXIT:
      log_to(g_svc_log, "exit_at=%.3f\n", abs_ms());
      ExitProcess(3);
    case SVC_CTL_FAILSTOP:
      log_to(g_svc_log, "failstop_at=%.3f\n", abs_ms());
      g_svc_exit_code = ERROR_SERVICE_SPECIFIC_ERROR;
      g_svc_specific = 7;
      SetEvent(g_svc_stop);
      return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
      return NO_ERROR;
    default:
      return ERROR_CALL_NOT_IMPLEMENTED;
  }
}

static wchar_t g_svc_dir[MAX_PATH * 2];

/* In the service (session 0, outside the runner's job): crash a child plain, in a job with
 * JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, and in a job without it; how long until each child is gone? */
static void svc_crash_lab(void) {
  for (int v = 0; v < 3; v++) {
    wchar_t lp[MAX_PATH * 2], args[MAX_PATH * 3];
    swprintf(lp, MAX_PATH * 2, L"%ls\\lab-%d.log", g_svc_dir, v);
    swprintf(args, MAX_PATH * 3, L"--crash-now \"%ls\"", lp);
    HANDLE job = NULL;
    if (v > 0) {
      job = CreateJobObjectW(NULL, NULL);
      JOBOBJECT_EXTENDED_LIMIT_INFORMATION x;
      memset(&x, 0, sizeof x);
      x.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | (v == 1 ? JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION : 0);
      SetInformationJobObject(job, JobObjectExtendedLimitInformation, &x, sizeof x);
    }
    PROCESS_INFORMATION pi;
    DWORD e = 0;
    if (!spawn_self(args, CREATE_SUSPENDED, NULL, &pi, &e)) { log_to(g_svc_log, "lab variant=%d spawn_err=%lu\n", v, (unsigned long)e); continue; }
    if (job) AssignProcessToJobObject(job, pi.hProcess);
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, 60000);
    char b[256] = "";
    read_text(lp, b, sizeof b);
    double tc = -1;
    char *q = strstr(b, "crash_at=");
    if (q) sscanf(q + 9, "%lf", &tc);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    log_to(g_svc_log, "lab variant=%d exit_after_crash_ms=%.0f code=0x%08lx\n", v, tc > 0 ? exit_after(pi.hProcess, tc) : -1.0, (unsigned long)code);
    kill_close(&pi);
    if (job) CloseHandle(job);
  }
  log_to(g_svc_log, "lab_done t=%.3f\n", abs_ms());
}

static void WINAPI svc_main(DWORD argc, LPWSTR *argv) {
  (void)argc; (void)argv;
  g_ssh = RegisterServiceCtrlHandlerExW(L"probe", svc_handler, NULL);
  if (!g_ssh) { log_to(g_svc_log, "register_handler_failed err=%lu\n", (unsigned long)GetLastError()); return; }
  svc_status(SERVICE_START_PENDING, 5000);
  int jobmode = wcscmp(g_svc_mode, L"job") == 0;
  HANDLE job = NULL;
  PROCESS_INFORMATION pi;
  DWORD e = 0;
  if (jobmode) {
    job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION x;
    memset(&x, 0, sizeof x);
    x.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &x, sizeof x);
    if (spawn_self(L"--child-sleep 120000", CREATE_SUSPENDED, NULL, &pi, &e)) {
      AssignProcessToJobObject(job, pi.hProcess);
      ResumeThread(pi.hThread);
    }
  } else {
    spawn_self(L"--child-sleep 120000", 0, NULL, &pi, &e);
  }
  BOOL in_job = FALSE, w_in_job = FALSE;
  IsProcessInJob(GetCurrentProcess(), NULL, &in_job);
  if (pi.hProcess) IsProcessInJob(pi.hProcess, NULL, &w_in_job);
  DWORD sess = 0, wsess = 0;
  ProcessIdToSessionId(GetCurrentProcessId(), &sess);
  if (pi.dwProcessId) ProcessIdToSessionId(pi.dwProcessId, &wsess);
  log_to(g_svc_log, "ready pid=%lu worker=%lu session=%lu worker_session=%lu in_job=%d worker_in_job=%d spawn_err=%lu t=%.3f\n", (unsigned long)GetCurrentProcessId(),
         (unsigned long)pi.dwProcessId, (unsigned long)sess, (unsigned long)wsess, (int)in_job, (int)w_in_job, (unsigned long)e, abs_ms());
  svc_status(SERVICE_RUNNING, 0);
  if (wcscmp(g_svc_mode, L"crashlab") == 0) svc_crash_lab();
  WaitForSingleObject(g_svc_stop, INFINITE);
  log_to(g_svc_log, "stopped_reported t=%.3f\n", abs_ms());
  svc_status(SERVICE_STOPPED, 0);
}

static int service_entry(const wchar_t *mode, const wchar_t *dir) {
  wcsncpy(g_svc_mode, mode, 31);
  wcsncpy(g_svc_dir, dir, MAX_PATH * 2 - 1);
  wchar_t lp[MAX_PATH * 2];
  swprintf(lp, MAX_PATH * 2, L"%ls\\svc.log", dir);
  g_svc_log = open_log(lp);
  g_svc_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
  log_to(g_svc_log, "process_start pid=%lu t=%.3f\n", (unsigned long)GetCurrentProcessId(), abs_ms());
  SERVICE_TABLE_ENTRYW t[] = {{(LPWSTR)L"probe", svc_main}, {NULL, NULL}};
  BOOL ok = StartServiceCtrlDispatcherW(t);
  log_to(g_svc_log, "dispatcher_returned ok=%d err=%lu t=%.3f\n", (int)ok, ok ? 0UL : (unsigned long)GetLastError(), abs_ms());
  return 0;
}

typedef struct { SC_HANDLE scm, svc; wchar_t name[80], dir[MAX_PATH * 2], log[MAX_PATH * 2]; } tsvc_t;
static int g_svc_n;

static BOOL svc_create(SC_HANDLE scm, tsvc_t *s, const wchar_t *mode, DWORD *err) {
  memset(s, 0, sizeof *s);
  s->scm = scm;
  g_svc_n++;
  swprintf(s->name, 80, L"pe-explore-%lu-%d", (unsigned long)GetCurrentProcessId(), g_svc_n);
  swprintf(s->dir, MAX_PATH * 2, L"%ls\\svc-%d", g_tmp, g_svc_n);
  CreateDirectoryW(s->dir, NULL);
  swprintf(s->log, MAX_PATH * 2, L"%ls\\svc.log", s->dir);
  wchar_t bin[4096];
  swprintf(bin, 4096, L"\"%ls\" --service %ls \"%ls\"", g_self, mode, s->dir);
  s->svc = CreateServiceW(scm, s->name, s->name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, bin, NULL, NULL, NULL, NULL, NULL);
  *err = s->svc ? 0 : GetLastError();
  return s->svc != NULL;
}

static void svc_recovery(tsvc_t *s, int noncrash_flag) {
  SC_ACTION acts[3] = {{SC_ACTION_RESTART, 1000}, {SC_ACTION_RESTART, 1000}, {SC_ACTION_NONE, 0}};
  SERVICE_FAILURE_ACTIONSW fa;
  memset(&fa, 0, sizeof fa);
  fa.dwResetPeriod = 86400;
  fa.cActions = 3;
  fa.lpsaActions = acts;
  ChangeServiceConfig2W(s->svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);
  SERVICE_FAILURE_ACTIONS_FLAG ff = {noncrash_flag ? TRUE : FALSE};
  ChangeServiceConfig2W(s->svc, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &ff);
}

static DWORD svc_state(tsvc_t *s, DWORD *pid) {
  SERVICE_STATUS_PROCESS sp;
  DWORD n = 0;
  if (QueryServiceStatusEx(s->svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&sp, sizeof sp, &n)) { if (pid) *pid = sp.dwProcessId; return sp.dwCurrentState; }
  if (pid) *pid = 0;
  return 0;
}

typedef struct { DWORD pid, worker, sess, wsess; int in_job, w_in_job; double t; } ready_t;

/* the nth "ready" line of the service log (1-based); waits up to ms */
static int svc_ready(tsvc_t *s, int nth, DWORD ms, ready_t *r) {
  static char buf[32768];
  double end = abs_ms() + ms;
  for (;;) {
    if (read_text(s->log, buf, sizeof buf) > 0) {
      char *p = buf;
      int k = 0;
      while ((p = strstr(p, "ready pid=")) != NULL) {
        if (++k == nth) {
          unsigned long a = 0, b = 0, c = 0, d = 0, e = 0;
          memset(r, 0, sizeof *r);
          sscanf(p, "ready pid=%lu worker=%lu session=%lu worker_session=%lu in_job=%d worker_in_job=%d spawn_err=%lu t=%lf", &a, &b, &c, &d, &r->in_job, &r->w_in_job, &e, &r->t);
          r->pid = a; r->worker = b; r->sess = c; r->wsess = d;
          return 1;
        }
        p++;
      }
    }
    if (abs_ms() > end) return 0;
    Sleep(20);
  }
}

static double log_time(tsvc_t *s, const char *key) {
  static char buf[32768];
  if (read_text(s->log, buf, sizeof buf) <= 0) return -1;
  char *p = strstr(buf, key);
  double t = -1;
  if (p) sscanf(p + strlen(key), "%lf", &t);
  return t;
}

static int count_ready(tsvc_t *s) {
  static char buf[32768];
  if (read_text(s->log, buf, sizeof buf) <= 0) return 0;
  int k = 0;
  for (char *p = buf; (p = strstr(p, "ready pid=")) != NULL; p++) k++;
  return k;
}

static HANDLE open_proc(DWORD pid) {
  return pid ? OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, pid) : NULL;
}

/* stop if running, kill every worker the log mentions, delete the service */
static void svc_cleanup(tsvc_t *s) {
  SERVICE_STATUS ss;
  DWORD pid = 0;
  if (svc_state(s, &pid) == SERVICE_RUNNING) ControlService(s->svc, SERVICE_CONTROL_STOP, &ss);
  for (int i = 0; i < 100 && svc_state(s, &pid) != SERVICE_STOPPED; i++) Sleep(50);
  if (pid) { HANDLE h = open_proc(pid); if (h) { TerminateProcess(h, 1); CloseHandle(h); } }
  ready_t r;
  int n = count_ready(s);
  for (int i = 1; i <= n; i++)
    if (svc_ready(s, i, 0, &r)) {
      HANDLE w = open_proc(r.worker);
      if (w) { TerminateProcess(w, 1); CloseHandle(w); }
      HANDLE p = open_proc(r.pid);
      if (p) { TerminateProcess(p, 1); CloseHandle(p); }
    }
  DeleteService(s->svc);
  CloseServiceHandle(s->svc);
  s->svc = NULL;
}

static int svc_start_ready(tsvc_t *s, const char *kase, ready_t *r, double *t_start) {
  *t_start = abs_ms();
  if (!StartServiceW(s->svc, 0, NULL)) { emit(kase, "\"start_error\":%lu", (unsigned long)GetLastError()); svc_cleanup(s); return 0; }
  if (!svc_ready(s, 1, 15000, r)) {
    char b[1024] = "";
    read_text(s->log, b, sizeof b);
    jsafe(b);
    emit(kase, "\"error\":\"no ready line within 15 s\",\"log\":\"%s\"", b);
    svc_cleanup(s);
    return 0;
  }
  return 1;
}

typedef struct { SC_HANDLE svc; DWORD ctl; BOOL ok; DWORD err; double t_ret; volatile LONG done; } ctl_call_t;
static DWORD WINAPI ctl_thread(LPVOID p) {
  ctl_call_t *c = (ctl_call_t *)p;
  SERVICE_STATUS ss;
  double t0 = abs_ms();
  c->ok = ControlService(c->svc, c->ctl, &ss);
  c->err = c->ok ? 0 : GetLastError();
  c->t_ret = abs_ms() - t0;
  InterlockedExchange(&c->done, 1);
  return 0;
}

static void svc_case_stop(SC_HANDLE scm, const char *kase, const wchar_t *mode, int try_cross_session) {
  tsvc_t s;
  DWORD err;
  if (!svc_create(scm, &s, mode, &err)) { emit(kase, "\"create_error\":%lu", (unsigned long)err); return; }
  ready_t r;
  double t_start;
  if (!svc_start_ready(&s, kase, &r, &t_start)) return;
  double start_to_ready = r.t - t_start;
  HANDLE hs = open_proc(r.pid), hw = open_proc(r.worker);
  char cross[256] = "null";
  if (try_cross_session) {
    /* AssignProcessToJobObject needs PROCESS_SET_QUOTA | PROCESS_TERMINATE on the process */
    HANDLE ha = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, r.worker);
    DWORD oe = ha ? 0 : GetLastError();
    HANDLE j = CreateJobObjectW(NULL, NULL);
    BOOL ok = ha && AssignProcessToJobObject(j, ha);
    DWORD ae = ok ? 0 : GetLastError();
    BOOL inj = FALSE;
    if (ok) IsProcessInJob(ha, j, &inj);
    snprintf(cross, sizeof cross, "{\"open_with_set_quota_error\":%lu,\"assign_session0_worker_to_session2_job_ok\":%s,\"error\":%lu,\"in_that_job_after\":%s}",
             (unsigned long)oe, bstr(ok), (unsigned long)ae, bstr(inj));
    CloseHandle(j);
    if (ha) CloseHandle(ha);
  }
  double t0 = abs_ms();
  /* the control runs on a thread; meanwhile record every change of (service state, process alive) */
  ctl_call_t cc;
  memset(&cc, 0, sizeof cc);
  cc.svc = s.svc;
  cc.ctl = SERVICE_CONTROL_STOP;
  HANDLE th = CreateThread(NULL, 0, ctl_thread, &cc, 0, NULL);
  char timeline[1500] = "";
  size_t tl = 0;
  DWORD last_state = 0xFFFF;
  int last_alive = -1;
  while (!cc.done && abs_ms() - t0 < 400000) {
    DWORD stn = svc_state(&s, NULL);
    int alive = hs && WaitForSingleObject(hs, 0) != WAIT_OBJECT_0;
    if ((stn != last_state || alive != last_alive) && tl < sizeof timeline - 64)
      tl += (size_t)snprintf(timeline + tl, sizeof timeline - tl, "%s%.0fms:state%lu:%s", tl ? "," : "", abs_ms() - t0, (unsigned long)stn, alive ? "alive" : "gone");
    last_state = stn;
    last_alive = alive;
    WaitForSingleObject(th, 100);
  }
  WaitForSingleObject(th, 30000);
  CloseHandle(th);
  BOOL cok = cc.ok;
  DWORD cerr = cc.err;
  double t_ret = cc.done ? cc.t_ret : -1;
  DWORD st_after_ret = svc_state(&s, NULL);
  double t_stopped = -1;
  for (int i = 0; i < 1000; i++) { if (svc_state(&s, NULL) == SERVICE_STOPPED) { t_stopped = abs_ms() - t0; break; } Sleep(10); }
  /* a handler that never returns: the process is still there after the control timed out? */
  int alive_5s_after = -1;
  double term_to_stopped = -1;
  if (wcscmp(mode, L"hang") == 0) {
    Sleep(5000);
    alive_5s_after = hs && WaitForSingleObject(hs, 0) != WAIT_OBJECT_0;
    if (alive_5s_after) {
      double tk = abs_ms();
      TerminateProcess(hs, 9);
      for (int i = 0; i < 500; i++) { if (svc_state(&s, NULL) == SERVICE_STOPPED) { term_to_stopped = abs_ms() - tk; break; } Sleep(10); }
    }
  }
  if (hs) WaitForSingleObject(hs, 10000);
  double svc_exit = exit_after(hs, t0);
  DWORD svc_code = 0;
  if (hs) GetExitCodeProcess(hs, &svc_code);
  Sleep(1000);
  int worker_alive = hw && WaitForSingleObject(hw, 0) != WAIT_OBJECT_0;
  double worker_exit = exit_after(hw, t0);
  emit(kase,
       "\"start_to_ready_ms\":%.0f,\"service_session\":%lu,\"worker_session\":%lu,\"service_in_job\":%d,\"worker_in_job\":%d,\"cross_session_assignment\":%s,"
       "\"control_stop_ok\":%s,\"control_error\":%lu,\"control_returned_after_ms\":%.0f,\"state_when_control_returned\":%lu,\"stopped_after_ms\":%.0f,"
       "\"service_process_exit_after_ms\":%.0f,\"service_exit_code\":\"0x%08lx\",\"timeline_while_control_pending\":\"%s\",\"hung_process_alive_5s_after_timeout\":%d,\"terminate_to_stopped_ms\":%.0f,\"worker_alive_1s_after_service_exit\":%s,\"worker_exit_after_ms\":%.0f",
       start_to_ready, (unsigned long)r.sess, (unsigned long)r.wsess, r.in_job, r.w_in_job, cross, bstr(cok), (unsigned long)cerr, t_ret, (unsigned long)st_after_ret, t_stopped,
       svc_exit, (unsigned long)svc_code, timeline, alive_5s_after, term_to_stopped, bstr(worker_alive), worker_exit);
  if (hs) CloseHandle(hs);
  if (hw) CloseHandle(hw);
  svc_cleanup(&s);
}

static const wchar_t *k_wer_key = L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\win_more.exe";

static void set_local_dumps(int dumptype, const wchar_t *dir) {
  RegDeleteKeyW(HKEY_LOCAL_MACHINE, k_wer_key);
  if (dumptype < 0) return;
  HKEY k;
  if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, k_wer_key, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL) != ERROR_SUCCESS) return;
  DWORD t = (DWORD)dumptype, cnt = 4;
  RegSetValueExW(k, L"DumpType", 0, REG_DWORD, (const BYTE *)&t, sizeof t);
  RegSetValueExW(k, L"DumpCount", 0, REG_DWORD, (const BYTE *)&cnt, sizeof cnt);
  RegSetValueExW(k, L"DumpFolder", 0, REG_EXPAND_SZ, (const BYTE *)dir, (DWORD)((wcslen(dir) + 1) * sizeof(wchar_t)));
  RegCloseKey(k);
}

static void dumps_in(const wchar_t *dir, int *count, double *mib) {
  wchar_t pat[MAX_PATH * 2];
  swprintf(pat, MAX_PATH * 2, L"%ls\\*.dmp", dir);
  WIN32_FIND_DATAW fd;
  HANDLE f = FindFirstFileW(pat, &fd);
  *count = 0;
  *mib = 0;
  if (f == INVALID_HANDLE_VALUE) return;
  do { (*count)++; *mib += ((double)fd.nFileSizeHigh * 4294967296.0 + fd.nFileSizeLow) / 1048576.0; } while (FindNextFileW(f, &fd));
  FindClose(f);
}

/* WerFault processes alive right now; their sessions as a bit mask */
static int wer_processes(DWORD *sessions) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return -1;
  PROCESSENTRY32W pe;
  pe.dwSize = sizeof pe;
  int n = 0;
  if (Process32FirstW(snap, &pe)) do {
    if (_wcsicmp(pe.szExeFile, L"WerFault.exe") == 0 || _wcsicmp(pe.szExeFile, L"WerFaultSecure.exe") == 0) {
      DWORD s = 0;
      ProcessIdToSessionId(pe.th32ProcessID, &s);
      if (s < 32) *sessions |= 1u << s;
      n++;
    }
  } while (Process32NextW(snap, &pe));
  CloseHandle(snap);
  return n;
}

/* wait for h, polling for WerFault meanwhile; returns ms waited */
static double wait_watching_wer(HANDLE h, DWORD ms, int *wer_max, DWORD *wer_sessions) {
  double t0 = abs_ms();
  *wer_max = 0;
  *wer_sessions = 0;
  while (abs_ms() - t0 < ms) {
    int n = wer_processes(wer_sessions);
    if (n > *wer_max) *wer_max = n;
    if (WaitForSingleObject(h, 25) == WAIT_OBJECT_0) break;
  }
  return abs_ms() - t0;
}

static void svc_case_failure(SC_HANDLE scm, const char *kase, DWORD ctl, int noncrash_flag, int dumptype) {
  tsvc_t s;
  DWORD err;
  if (!svc_create(scm, &s, L"plain", &err)) { emit(kase, "\"create_error\":%lu", (unsigned long)err); return; }
  svc_recovery(&s, noncrash_flag);
  set_local_dumps(dumptype, s.dir);
  ready_t r;
  double t_start;
  if (!svc_start_ready(&s, kase, &r, &t_start)) { set_local_dumps(-1, NULL); return; }
  HANDLE hs = open_proc(r.pid), hw = open_proc(r.worker);
  double t0 = abs_ms();
  SERVICE_STATUS ss;
  BOOL cok = ControlService(s.svc, ctl, &ss);
  DWORD cerr = cok ? 0 : GetLastError();
  double t_ret = abs_ms() - t0;
  int wer_max = 0;
  DWORD wer_sess = 0;
  if (hs) wait_watching_wer(hs, 60000, &wer_max, &wer_sess);
  const char *key = ctl == SVC_CTL_CRASH ? "crash_at=" : ctl == SVC_CTL_EXIT ? "exit_at=" : "failstop_at=";
  double t_event = log_time(&s, key);
  double exit_from_event = t_event > 0 ? exit_after(hs, t_event) : -1;
  double t_exit_abs = exit_after(hs, 0);
  /* recovery: a second instance? */
  ready_t r2;
  int restarted = svc_ready(&s, 2, 8000, &r2);
  double restart_after_exit = restarted && t_exit_abs > 0 ? r2.t - t_exit_abs : -1;
  int old_worker_alive_at_restart = hw && WaitForSingleObject(hw, 0) != WAIT_OBJECT_0;
  DWORD st = svc_state(&s, NULL);
  int dumps = 0;
  double dump_mib = 0;
  dumps_in(s.dir, &dumps, &dump_mib);
  DWORD code = 0;
  if (hs) GetExitCodeProcess(hs, &code);
  emit(kase,
       "\"local_dumps_type\":%d,\"failure_actions_on_non_crash\":%d,\"control_ok\":%s,\"control_error\":%lu,\"control_returned_after_ms\":%.0f,"
       "\"service_process_exit_after_event_ms\":%.0f,\"exit_code\":\"0x%08lx\",\"werfault_processes_seen\":%d,\"werfault_session_mask\":\"0x%lx\",\"dumps\":%d,\"dump_MiB\":%.1f,"
       "\"restarted\":%s,\"restart_ready_after_exit_ms\":%.0f,\"old_worker_alive_at_restart\":%s,\"state_now\":%lu",
       dumptype, noncrash_flag, bstr(cok), (unsigned long)cerr, t_ret, exit_from_event, (unsigned long)code, wer_max, (unsigned long)wer_sess, dumps, dump_mib,
       bstr(restarted), restart_after_exit, bstr(old_worker_alive_at_restart), (unsigned long)st);
  if (hs) CloseHandle(hs);
  if (hw) CloseHandle(hw);
  svc_cleanup(&s);
  set_local_dumps(-1, NULL);
}

static int crash_now(const wchar_t *logpath) {
  HANDLE log = open_log(logpath);
  log_to(log, "crash_at=%.3f\n", abs_ms());
  volatile int *p = NULL;
  *p = 1;
  return 0;
}

/* the same crash in an ordinary child in this (interactive) session, for comparison */
static void plain_crash_case_flags(const char *kase, int dumptype, DWORD flags);
static void plain_crash_case(const char *kase, int dumptype) { plain_crash_case_flags(kase, dumptype, 0); }
static void plain_crash_case_flags(const char *kase, int dumptype, DWORD flags) {
  wchar_t dir[MAX_PATH * 2], logp[MAX_PATH * 2], args[MAX_PATH * 3];
  swprintf(dir, MAX_PATH * 2, L"%ls\\plain-crash-%d", g_tmp, dumptype + 1);
  CreateDirectoryW(dir, NULL);
  swprintf(logp, MAX_PATH * 2, L"%ls\\crash.log", dir);
  set_local_dumps(dumptype, dir);
  swprintf(args, MAX_PATH * 3, L"--crash-now \"%ls\"", logp);
  PROCESS_INFORMATION pi;
  DWORD e;
  if (!spawn_self(args, flags, NULL, &pi, &e)) { emit(kase, "\"spawn_error\":%lu", (unsigned long)e); set_local_dumps(-1, NULL); return; }
  BOOL child_in_job = FALSE;
  IsProcessInJob(pi.hProcess, NULL, &child_in_job);
  int wer_max = 0;
  DWORD wer_sess = 0;
  wait_watching_wer(pi.hProcess, 60000, &wer_max, &wer_sess);
  char b[256] = "";
  read_text(logp, b, sizeof b);
  double t_crash = -1;
  char *q = strstr(b, "crash_at=");
  if (q) sscanf(q + 9, "%lf", &t_crash);
  double ex = t_crash > 0 ? exit_after(pi.hProcess, t_crash) : -1;
  DWORD code = 0;
  GetExitCodeProcess(pi.hProcess, &code);
  int dumps = 0;
  double mib = 0;
  dumps_in(dir, &dumps, &mib);
  DWORD sess = 0;
  ProcessIdToSessionId(GetCurrentProcessId(), &sess);
  emit(kase, "\"session\":%lu,\"child_in_a_job\":%s,\"local_dumps_type\":%d,\"process_exit_after_crash_ms\":%.0f,\"exit_code\":\"0x%08lx\",\"werfault_processes_seen\":%d,\"werfault_session_mask\":\"0x%lx\",\"dumps\":%d,\"dump_MiB\":%.1f",
       (unsigned long)sess, bstr(child_in_job), dumptype, ex, (unsigned long)code, wer_max, (unsigned long)wer_sess, dumps, mib);
  kill_close(&pi);
  set_local_dumps(-1, NULL);
}

static void svc_case_crashlab(SC_HANDLE scm, const char *kase, int dumptype) {
  tsvc_t s;
  DWORD err;
  if (!svc_create(scm, &s, L"crashlab", &err)) { emit(kase, "\"create_error\":%lu", (unsigned long)err); return; }
  set_local_dumps(dumptype, s.dir);
  ready_t r;
  double t_start;
  if (!svc_start_ready(&s, kase, &r, &t_start)) { set_local_dumps(-1, NULL); return; }
  static char buf[32768];
  double end = abs_ms() + 120000;
  while (abs_ms() < end) { if (read_text(s.log, buf, sizeof buf) > 0 && strstr(buf, "lab_done")) break; Sleep(100); }
  char res[600] = "";
  size_t l = 0;
  static const char *names[] = {"no_job", "job_with_DIE_ON_UNHANDLED_EXCEPTION", "job_without_it"};
  for (int v = 0; v < 3; v++) {
    char key[32];
    snprintf(key, sizeof key, "lab variant=%d ", v);
    char *q = strstr(buf, key);
    double ms = -1;
    unsigned long code = 0;
    if (q) sscanf(q + strlen(key), "exit_after_crash_ms=%lf code=0x%lx", &ms, &code);
    l += (size_t)snprintf(res + l, sizeof res - l, "%s\"%s\":{\"exit_after_crash_ms\":%.0f,\"exit_code\":\"0x%08lx\"}", v ? "," : "", names[v], ms, code);
  }
  int dumps = 0;
  double mib = 0;
  dumps_in(s.dir, &dumps, &mib);
  emit(kase, "\"where\":\"children of a session-0 service, outside the runner's job\",\"local_dumps_type\":%d,%s,\"dumps\":%d,\"dump_MiB\":%.1f", dumptype, res, dumps, mib);
  svc_cleanup(&s);
  set_local_dumps(-1, NULL);
}

static void runner_job(void) {
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION x;
  memset(&x, 0, sizeof x);
  BOOL ok = QueryInformationJobObject(NULL, JobObjectExtendedLimitInformation, &x, sizeof x, NULL); /* NULL = the caller's job */
  DWORD e = ok ? 0 : GetLastError();
  DWORD f = x.BasicLimitInformation.LimitFlags;
  emit("runner_job_of_this_process", "\"query_ok\":%s,\"error\":%lu,\"limit_flags\":\"0x%lx\",\"die_on_unhandled_exception\":%s,\"breakaway_ok\":%s,\"silent_breakaway_ok\":%s,\"kill_on_job_close\":%s",
       bstr(ok), (unsigned long)e, (unsigned long)f, bstr((f & JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION) != 0), bstr((f & JOB_OBJECT_LIMIT_BREAKAWAY_OK) != 0),
       bstr((f & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) != 0), bstr((f & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0));
}

static void reg_dword(HKEY root, const wchar_t *path, const wchar_t *name, char *out, size_t n) {
  HKEY k;
  DWORD v = 0, sz = sizeof v, type = 0;
  if (RegOpenKeyExW(root, path, 0, KEY_READ, &k) != ERROR_SUCCESS) { snprintf(out, n, "\"no key\""); return; }
  wchar_t sv[256];
  DWORD ssz = sizeof sv;
  LONG r = RegQueryValueExW(k, name, NULL, &type, (LPBYTE)sv, &ssz);
  if (r != ERROR_SUCCESS) snprintf(out, n, "\"absent\"");
  else if (type == REG_DWORD) { memcpy(&v, sv, sizeof v); snprintf(out, n, "%lu", (unsigned long)v); (void)sz; }
  else if (type == REG_SZ || type == REG_EXPAND_SZ) { char a[512]; wtext(sv, a, sizeof a); snprintf(out, n, "\"%s\"", a); }
  else snprintf(out, n, "\"type %lu\"", (unsigned long)type);
  RegCloseKey(k);
}

static void probe_services(void) {
  char a[300], b[300], c[300], d[300], e2[300], f[300];
  const wchar_t *wer = L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting";
  reg_dword(HKEY_LOCAL_MACHINE, wer, L"Disabled", a, sizeof a);
  reg_dword(HKEY_LOCAL_MACHINE, wer, L"DontShowUI", b, sizeof b);
  reg_dword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps", L"DumpType", c, sizeof c);
  reg_dword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control", L"WaitToKillServiceTimeout", d, sizeof d);
  reg_dword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control", L"ServicesPipeTimeout", e2, sizeof e2);
  reg_dword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\Consent", L"DefaultConsent", f, sizeof f);
  emit("services_context", "\"elevated\":%s,\"wer_disabled\":%s,\"wer_dont_show_ui\":%s,\"wer_consent_default\":%s,\"global_local_dumps_type\":%s,\"WaitToKillServiceTimeout\":%s,\"ServicesPipeTimeout\":%s",
       bstr(is_elevated()), a, b, f, c, d, e2);
  runner_job();
  int dbg = enable_privilege(L"SeDebugPrivilege");
  SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
  if (!scm) { emit("services_unavailable", "\"open_scm_error\":%lu,\"debug_privilege\":%d", (unsigned long)GetLastError(), dbg); return; }
  svc_case_stop(scm, "service_stop_worker_without_job", L"plain", 1);
  svc_case_stop(scm, "service_stop_worker_in_kill_on_close_job", L"job", 0);
  svc_case_stop(scm, "service_stop_handler_never_returns", L"hang", 0);
  svc_case_failure(scm, "service_crash_with_restart_action_no_local_dumps", SVC_CTL_CRASH, 0, -1);
  svc_case_failure(scm, "service_crash_with_restart_action_minidump", SVC_CTL_CRASH, 0, 1);
  svc_case_failure(scm, "service_crash_with_restart_action_full_dump", SVC_CTL_CRASH, 0, 2);
  svc_case_failure(scm, "service_exitprocess_without_reporting_stopped", SVC_CTL_EXIT, 0, -1);
  svc_case_failure(scm, "service_reports_stopped_with_error_noncrash_flag_off", SVC_CTL_FAILSTOP, 0, -1);
  svc_case_failure(scm, "service_reports_stopped_with_error_noncrash_flag_on", SVC_CTL_FAILSTOP, 1, -1);
  svc_case_crashlab(scm, "crash_lab_no_local_dumps", -1);
  svc_case_crashlab(scm, "crash_lab_minidump", 1);
  CloseServiceHandle(scm);
  plain_crash_case("interactive_child_crash_no_local_dumps", -1);
  plain_crash_case("interactive_child_crash_minidump", 1);
  plain_crash_case("interactive_child_crash_full_dump", 2);
  plain_crash_case_flags("interactive_child_crash_breakaway_from_runner_job_minidump", 1, CREATE_BREAKAWAY_FROM_JOB);
}

/* ================================================================== exitproc */
typedef void (*cfg_fn)(int, HANDLE);

static int exitproc_child(int mode, const wchar_t *logpath) {
  HANDLE log = open_log(logpath);
  wchar_t dll[MAX_PATH * 2];
  wcscpy(dll, g_self);
  wchar_t *slash = wcsrchr(dll, L'\\');
  if (slash) wcscpy(slash + 1, L"detach_dll.dll");
  HMODULE m = LoadLibraryW(dll);
  if (!m) { log_to(log, "loadlibrary_failed err=%lu\n", (unsigned long)GetLastError()); return 90; }
  cfg_fn cfg = (cfg_fn)(void *)GetProcAddress(m, "detach_configure");
  LPTHREAD_START_ROUTINE hold = (LPTHREAD_START_ROUTINE)(void *)GetProcAddress(m, "detach_hold");
  if (!cfg || !hold) { log_to(log, "exports_missing\n"); return 91; }
  cfg(mode, log);
  HANDLE ready = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (mode != 0) CreateThread(NULL, 0, hold, ready, 0, NULL);
  else SetEvent(ready);
  WaitForSingleObject(ready, 5000);
  log_to(log, "exit_call t=%.3f value=0\n", abs_ms());
  ExitProcess(0);
}

static void probe_exitproc(void) {
  static const char *names[] = {"no_lock", "critical_section_held_by_terminated_thread", "srw_lock_held_by_terminated_thread",
                                "event_owed_by_terminated_thread", "mutex_held_by_terminated_thread", "slow_detach_1500ms", "detach_waits_for_terminated_worker_handle"};
  for (int mode = 0; mode < 7; mode++) {
    wchar_t logp[MAX_PATH * 2], args[MAX_PATH * 3], ln[64];
    swprintf(ln, 64, L"exitproc-%d.log", mode);
    swprintf(logp, MAX_PATH * 2, L"%ls\\%ls", g_tmp, ln);
    DeleteFileW(logp);
    swprintf(args, MAX_PATH * 3, L"--exitproc-child %d \"%ls\"", mode, logp);
    PROCESS_INFORMATION pi;
    DWORD e;
    char kase[96];
    snprintf(kase, sizeof kase, "exitprocess_%s", names[mode]);
    if (!spawn_self(args, 0, NULL, &pi, &e)) { emit(kase, "\"spawn_error\":%lu", (unsigned long)e); continue; }
    int exited = WaitForSingleObject(pi.hProcess, 6000) == WAIT_OBJECT_0;
    double term_ms = -1;
    if (!exited) {
      double tk = abs_ms();
      TerminateProcess(pi.hProcess, 99);
      WaitForSingleObject(pi.hProcess, 5000);
      term_ms = abs_ms() - tk;
    }
    char b[2048] = "";
    read_text(logp, b, sizeof b);
    double t_call = -1, t_ds = -1, t_de = -1;
    unsigned long dv = 0;
    char *q;
    if ((q = strstr(b, "exit_call t="))) sscanf(q + 12, "%lf", &t_call);
    if ((q = strstr(b, "detach_start t="))) sscanf(q + 15, "%lf", &t_ds);
    if ((q = strstr(b, "detach_end t="))) sscanf(q + 13, "%lf value=%lu", &t_de, &dv);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    double ex = t_call > 0 ? exit_after(pi.hProcess, t_call) : -1;
    jsafe(b);
    emit(kase, "\"exited_by_itself_within_6s\":%s,\"exit_after_exit_call_ms\":%.0f,\"exit_code\":\"0x%08lx\",\"detach_started_after_ms\":%.0f,\"detach_finished_after_ms\":%.0f,\"detach_wait_result\":%lu,\"terminate_needed\":%s,\"terminate_to_exit_ms\":%.0f,\"log\":\"%s\"",
         bstr(exited), ex, (unsigned long)code, t_ds > 0 && t_call > 0 ? t_ds - t_call : -1, t_de > 0 && t_call > 0 ? t_de - t_call : -1, dv, bstr(!exited), term_ms, b);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
  }
}

/* ================================================================== main */
static DWORD WINAPI watchdog_thread(LPVOID p) {
  (void)p;
  Sleep(600000);
  emit("_watchdog", "\"error\":\"probe exceeded 600 s and was stopped\"");
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
  BOOL in_job = FALSE;
  IsProcessInJob(GetCurrentProcess(), NULL, &in_job);
  DWORD session = 0;
  ProcessIdToSessionId(GetCurrentProcessId(), &session);
  SYSTEM_INFO si;
  GetNativeSystemInfo(&si);
  emit("_platform", "\"windows\":\"%lu.%lu.%lu\",\"native_arch\":%u,\"elevated\":%s,\"in_job\":%s,\"session_id\":%lu", (unsigned long)v.dwMajorVersion,
       (unsigned long)v.dwMinorVersion, (unsigned long)v.dwBuildNumber, (unsigned)si.wProcessorArchitecture, bstr(is_elevated()), bstr(in_job), (unsigned long)session);
}

int main(void) {
  int argc = 0;
  wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  init_paths();
  if (argc >= 3 && wcscmp(argv[1], L"--child-sleep") == 0) { RemoveDirectoryW(g_tmp); Sleep((DWORD)_wtoi(argv[2])); return 0; }
  if (argc >= 4 && wcscmp(argv[1], L"--service") == 0) { RemoveDirectoryW(g_tmp); return service_entry(argv[2], argv[3]); }
  if (argc >= 4 && wcscmp(argv[1], L"--exitproc-child") == 0) { RemoveDirectoryW(g_tmp); return exitproc_child(_wtoi(argv[2]), argv[3]); }
  if (argc >= 3 && wcscmp(argv[1], L"--crash-now") == 0) { RemoveDirectoryW(g_tmp); return crash_now(argv[2]); }

  CreateThread(NULL, 0, watchdog_thread, NULL, 0, NULL);
  const wchar_t *which = argc >= 2 ? argv[1] : L"";
  header();
  if (wcscmp(which, L"priority") == 0) probe_priority();
  else if (wcscmp(which, L"desktop") == 0) probe_desktop();
  else if (wcscmp(which, L"services") == 0) probe_services();
  else if (wcscmp(which, L"exitproc") == 0) probe_exitproc();
  else emit("_usage", "\"error\":\"usage: win_more priority|desktop|services|exitproc\"");
  return 0;
}
