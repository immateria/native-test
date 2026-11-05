/* Prints each argument it received (argv[1..]) as UTF-16 code units in hex, one per line, to the file named by
   ARGDUMP_OUT, or to stdout. Built with cl.exe, so the parsing is the Universal CRT's. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int wmain(int argc, wchar_t **argv) {
  const wchar_t *out = _wgetenv(L"ARGDUMP_OUT");
  FILE *f = stdout;
  if (out && *out) { if (_wfopen_s(&f, out, L"wb") != 0) return 3; }
  for (int i = 1; i < argc; i++) {
    for (const wchar_t *p = argv[i]; *p; p++) fprintf(f, "%04x", (unsigned)*p);
    fputc('\n', f);
  }
  if (f != stdout) fclose(f);
  return 0;
}
