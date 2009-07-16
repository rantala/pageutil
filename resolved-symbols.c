/* This application goes through the ELF libraries and binaries that a process
 * has mapped to memory, and for each such ELF file, it discovers whether the
 * undefined symbols (those from the PLT table) have yet been resolved.
 *
 * Symbol resolution is by default lazy, ie. the actual address is resolved
 * when the external function is called for the first time. In other words,
 * with this tool it is possible to determine what external functions have been
 * called at least once from each ELF library and binary.
 *
 * Notes:
 *  - We need information from the ELF files, and from the process's memory.
 *    For the memory access we use ptrace() calls (note that /proc/pid/mem has
 *    limitation for accessing other process's memories).
 *  - We use the ''readelf'' and ''objdump'' utilities for gathering
 *    information from ELF files.
 *
 * Copyright (C) 2009 Tommi Rantala <tt.rantala@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA
 */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#define PROGNAME "resolved-symbols"

/* Represents one entry from the Procedure Linkage Table (PLT). We read the
 * symbols from the PLT with objdump. In order to figure out if the symbol has
 * been resolved, we have to read the process's memory, and look for the Global
 * Offset Tables (GOT).
 *
 *   symbol   : Symbol name, eg. "waitpid", "strcpy", or "g_object_ref".
 *              Dynamically allocated.
 *   resolved : Has the particular ELF object resolved the actual address of
 *              the symbol?
 */
typedef struct
{
	char *symbol;
	unsigned resolved;
} pltsym_t;

/* Virtual memory area from /proc/pid/maps, eg. b7f59000-b7f5a000.
 */
typedef struct
{
	unsigned long begin;
	unsigned long end;
} vma_t;

/* One of these structs are allocated for each ELF object that the process has
 * mapped to memory. 
 *
 * In the following example, these structs would be created for '/bin/cat',
 * '/lib/tls/i686/cmov/libc-2.9.so' and '/lib/ld-2.9.so'.
 *  
 *   $ cat /proc/self/maps
 *   08048000-0804f000 r-xp 00000000 08:01 416994     /bin/cat
 *   0804f000-08050000 r--p 00006000 08:01 416994     /bin/cat
 *   08050000-08051000 rw-p 00007000 08:01 416994     /bin/cat
 *   099c9000-099ea000 rw-p 099c9000 00:00 0          [heap]
 *   b7dcb000-b7e0a000 r--p 00000000 08:01 409884     /usr/lib/locale/en_US.utf8/LC_CTYPE
 *   b7e0a000-b7ef5000 r--p 00000000 08:01 409883     /usr/lib/locale/en_US.utf8/LC_COLLATE
 *   b7ef5000-b7ef6000 rw-p b7ef5000 00:00 0
 *   b7ef6000-b8052000 r-xp 00000000 08:01 483739     /lib/tls/i686/cmov/libc-2.9.so
 *   b8052000-b8053000 ---p 0015c000 08:01 483739     /lib/tls/i686/cmov/libc-2.9.so
 *   b8053000-b8055000 r--p 0015c000 08:01 483739     /lib/tls/i686/cmov/libc-2.9.so
 *   b8055000-b8056000 rw-p 0015e000 08:01 483739     /lib/tls/i686/cmov/libc-2.9.so
 *   b806d000-b806e000 r-xp b806d000 00:00 0          [vdso]
 *   b806e000-b808a000 r-xp 00000000 08:01 466055     /lib/ld-2.9.so
 *   b808a000-b808b000 r--p 0001b000 08:01 466055     /lib/ld-2.9.so
 *   b808b000-b808c000 rw-p 0001c000 08:01 466055     /lib/ld-2.9.so
 *   bf976000-bf98b000 rw-p bffeb000 00:00 0          [stack]
 *
 * The fields are:
 *    path              : Full path to the ELF object, eg. "/bin/cat".
 *                        Dynamically allocated.
 *    word_size         : Word size in bytes, ie. ELF32/ELF64.
 *    elf_plt_off       : .plt section offset (read from the ELF file).
 *    elf_ptl_len       : .plt section size in bytes.
 *    elf_got_plt_off   : .plt.got section offset (read from the ELF file).
 *    elf_got_plt_len   : .plt.got section size in bytes.
 *    vmas              : Virtual memory areas that this library is mapped to
 *                        in the process's memory.
 *    vmas_cnt          : Counter for the VMAs.
 *    pltsyms           : Symbols from the PLT.
 *    pltsyms_cnt       : Counter for the PLT symbols.
 */
typedef struct
{
	char *path;
	unsigned word_size;
	unsigned long elf_plt_off;
	unsigned long elf_plt_len;
	unsigned long elf_got_plt_off;
	unsigned long elf_got_plt_len;
	vma_t *vmas;
	pltsym_t *pltsyms;
	unsigned vmas_cnt;
	unsigned pltsyms_cnt;
} library_t;

static int
libname_cmp(const void *a, const void *b)
{
	const library_t *l1 = a;
	const library_t *l2 = b;
	return strcmp(l1->path, l2->path);
}

static int
symname_cmp(const void *a, const void *b)
{
	const pltsym_t *s1 = a;
	const pltsym_t *s2 = b;
	return strcmp(s1->symbol, s2->symbol);
}

static void
lib_info_pltsyms(library_t* lib)
{
	char *cmd, *line=NULL;
	size_t line_n=0;
	if (asprintf(&cmd, "objdump -C -d -j .plt %s | grep \"@plt>:$\"", lib->path) == -1) {
		fprintf(stderr, PROGNAME ": ERROR: asprintf() failure.\n");
		exit(1);
	}
	FILE* fp = popen(cmd, "r");
	free(cmd);
	if (fp == NULL) {
		fprintf(stderr, PROGNAME ": ERROR: popen() failure.\n");
		exit(1);
	}
	while (getline(&line, &line_n, fp) != -1) {
		pltsym_t sym;
		char *p, *end;
		unsigned long offset;
		memset(&sym, 0, sizeof(pltsym_t));
		errno = 0;
		offset = strtoul(line, &p, 16);
		if (errno) break;
		p = strchr(p, '<');
		if (p == NULL) break;
		++p;
		end = strstr(p, "@plt>:");
		if (end == NULL) break;
		*end = 0;
		sym.symbol = strdup(p);
		++lib->pltsyms_cnt;
		pltsym_t *re = (pltsym_t *)realloc(lib->pltsyms, lib->pltsyms_cnt * sizeof(pltsym_t));
		if (re == NULL) {
			fprintf(stderr, PROGNAME ": ERROR: realloc() failure.\n");
			exit(1);
		}
		lib->pltsyms = re;
		memcpy(&lib->pltsyms[lib->pltsyms_cnt-1], &sym, sizeof(pltsym_t));
	}
	free(line);
	pclose(fp);
}

static void
lib_info_plt(library_t* lib)
{
	char* cmd = NULL;
	char* line = NULL;
	size_t line_n = 0;
	if (asprintf(&cmd, "readelf -WS %s", lib->path) == -1) {
		fprintf(stderr, PROGNAME ": ERROR: asprintf() failure.\n");
		exit(1);
	}
	FILE* fp = popen(cmd, "r");
	free(cmd);
	if (fp == NULL) {
		fprintf(stderr, PROGNAME ": ERROR: popen() failure.\n");
		exit(1);
	}
	unsigned long plt=0, plt_len=0, got_plt=0, got_plt_len=0;
	while (getline(&line, &line_n, fp) != -1) {
		if (strstr(line, " .plt ") != NULL) {
			sscanf(line, "%*s .plt %*s %lx %*x %lx",
					&plt, &plt_len);
		} else if (strstr(line, " .got.plt ") != NULL) {
			sscanf(line, "%*s .got.plt %*s %lx %*x %lx",
					&got_plt, &got_plt_len);
		}
		if (plt && got_plt) break;
	}
	free(line);
	for (size_t i=0; i < lib->vmas_cnt; ++i) {
		if (plt >= lib->vmas[i].begin && plt < lib->vmas[i].end)
			plt = plt - lib->vmas[0].begin;
		if (got_plt >= lib->vmas[i].begin && got_plt < lib->vmas[i].end)
			got_plt = got_plt - lib->vmas[0].begin;
	}
	//fprintf(stderr, "%s:     .plt at offset 0x%08lx\n", lib->path, plt);
	//fprintf(stderr, "%s: .got.plt at offset 0x%08lx\n", lib->path, got_plt);
	lib->elf_plt_off = plt;
	lib->elf_plt_len = plt_len;
	lib->elf_got_plt_off = got_plt;
	lib->elf_got_plt_len = got_plt_len;
	fclose(fp);
}

static void
lib_info(library_t *lib)
{
	lib_info_plt(lib);
	lib_info_pltsyms(lib);
}

/* Checks the first 5 bytes from the given file to determine if it looks like
 * an ELF object. Returns 1 if it does, 0 otherwise.
 */
static unsigned
elf_info(const char* path, unsigned *word_size)
{
	char header[5];
	int ret = 0;
	FILE *fp = fopen(path, "r");
	if (fp == NULL) goto nogood;
	if (fread(header, 1, 5, fp) != 5) goto nogood;
	if (header[0] == 0x7f &&
	    header[1] == 'E' &&
	    header[2] == 'L' &&
	    header[3] == 'F') {
		if (header[4] == 1) { *word_size = 4; }
		else if (header[4] == 2) { *word_size = 8; }
		else goto nogood;
		ret = 1;
	}
nogood:
	if (fp) fclose(fp);
	return ret;
}

static void
getlibs(int pid, library_t **libs_, unsigned *libs_cnt_)
{
	library_t *libs = NULL;
	FILE *fp = NULL;
	unsigned libs_cnt = 0;
	char *maps = NULL, *line = NULL;
	size_t line_n = 0;
	if (asprintf(&maps, "/proc/%d/maps", pid) == -1) {
		fprintf(stderr, PROGNAME ": ERROR: asprintf() failure.\n");
		exit(1);
	}
	if ((fp = fopen(maps, "r")) == NULL) goto done;
	while (getline(&line, &line_n, fp) != -1) {
		char* f = strchr(line, '/');
		if (f == NULL) continue;
		size_t flen = strlen(f);
		if (flen > 1 && f[flen-1] == '\n') f[flen-1] = 0;
		size_t i=0;
		for (i=0; i < libs_cnt; ++i) {
			if (strcmp(libs[i].path, f) == 0) {
				break;
			}
		}
		vma_t v = {0,0};
		if (sscanf(line, "%lx-%lx", &v.begin, &v.end) != 2) continue;
		if (i < libs_cnt) {
			++libs[i].vmas_cnt;
			libs[i].vmas = (vma_t *)realloc(libs[i].vmas,
					libs[i].vmas_cnt * sizeof(vma_t));
			memcpy(libs[i].vmas+libs[i].vmas_cnt-1, &v, sizeof(vma_t));
			continue;
		}
		unsigned word_size = 0;
		if (!elf_info(f, &word_size)) continue;
		libs = (library_t *)realloc(libs, (libs_cnt+1)*sizeof(library_t));
		memset(&libs[libs_cnt], 0, sizeof(library_t));
		libs[libs_cnt].path = strdup(f);
		libs[libs_cnt].word_size = word_size;
		libs[libs_cnt].vmas = (vma_t *)malloc(sizeof(vma_t));
		libs[libs_cnt].vmas_cnt = 1;
		memcpy(libs[libs_cnt].vmas, &v, sizeof(vma_t));
		++libs_cnt;
	}
done:
	free(maps);
	free(line);
	if (fp != NULL) fclose(fp);
	for (size_t i=0; i < libs_cnt; ++i) {
		lib_info(&libs[i]);
	}
	*libs_ = libs;
	*libs_cnt_ = libs_cnt;
}

static unsigned
pltsym_resolved(const library_t* lib, size_t num, int pid)
{
	assert(num < lib->pltsyms_cnt);
	// Skip the first three words from the .got.plt, the actual entries
	// begin after those.
	unsigned long entry_addr = lib->vmas[0].begin + lib->elf_got_plt_off
		+ 3*lib->word_size + num*lib->word_size;
	//fprintf(stderr, "%s(): peeking @ %p\n", __func__, (void*)entry_addr);
	long p = ptrace(PTRACE_PEEKDATA, pid, entry_addr, NULL);
	if (p == -1) {
		fprintf(stderr, "[%d]: ptrace() peekdata failure: %s\n",
				pid, strerror(errno));
		return 0;
	}
	unsigned long entry = p;
	//fprintf(stderr, "   ............... 0x%08lx\n", entry);
	if (entry >= (lib->vmas[0].begin + lib->elf_plt_off) &&
	    entry <  (lib->vmas[0].begin + lib->elf_plt_off + lib->elf_plt_len))
		return 0;
	return 1;
}

/* Dynamic linker variables LD_BIND_NOW and LD_BIND_NOT affect symbol
 * resolution and PLT and GOT updating. Check whether the process has these
 * environment variables defined.
 */
static const char*
check_environ(int pid)
{
	FILE *fp = NULL;
	char *env, *line = NULL;
	size_t line_n = 0;
	int ld_bind_now = 0, ld_bind_not = 0;
	if (asprintf(&env, "/proc/%d/environ", pid) == -1) goto done;
	if ((fp = fopen(env, "r")) == NULL) goto done;
	while (getdelim(&line, &line_n, 0, fp) != -1) {
		if (strstr(line, "LD_BIND_NOW=") == line) {
			ld_bind_now=1;
		} else if (strstr(line, "LD_BIND_NOT=") == line) {
			ld_bind_not=1;
		}
	}
done:
	free(env);
	free(line);
	if (fp != NULL) fclose(fp);
	if (ld_bind_now) return " [LD_BIND_NOW]";
	if (ld_bind_not) return " [LD_BIND_NOT]";
	return "";
}

static void
usage()
{
	fprintf(stderr,
"resolved-symbols: Show whether undefined symbols from ELF files that a\n"
"                  process has mapped have been resolved. In most cases\n"
"                  a symbol is resolved when the function is called for\n"
"                  the first time.\n"
"\n"
"Usage:\n"
"           resolved-symbols <pid> [<pid> ...]\n"
"\n"
"           -y, --resolved       Only show resolved symbols.\n"
"           -n, --unresolved     Only show unresolved symbols.\n"
"\n"
"           -S, --sort-elfs      Alphabetically sort the ELF files before\n"
"                                displaying results, instead of using the\n"
"                                order the files appear in /proc/pid/maps.\n"
"           -S, --sort-syms      Alphabetically sort the symbols for each\n"
"                                ELF file before displaying results, instead\n"
"                                of using the order in which they have\n"
"                                appear in the file.\n"
"\n"
"               --grep=REGEX     Only show mapped ELF files that match the\n"
"                                regular expression REGEX. See /proc/pid/maps.\n"
"\n"
"Note: Dynamic linker environment variables LD_BIND_NOW and LD_BIND_NOT\n"
"      affect the symbol resolution process. If these variables have been\n"
"      defined, results may vary.\n");
}

static const struct option long_options[] = {
	{"resolved", 0, 0, 'y'},
	{"unresolved", 0, 0, 'n'},
	{"sort-elfs", 0, 0, 'S'},
	{"sort-syms", 0, 0, 's'},
	{"grep", 1, 0, 256},
	{"help", 0, 0, 'h'},
	{0, 0, 0, 0}
};

int main(int argc, char** argv)
{
	regex_t regex;
	int opt, resolved_only=0, unresolved_only=0, sort_elfs=0, sort_syms=0, use_regex=0;
	while ((opt = getopt_long(argc, argv, "ynSsh",
			long_options, NULL)) != -1) {
		switch(opt) {
		case 'y':
			resolved_only=1;
			break;
		case 'n':
			unresolved_only=1;
			break;
		case 'S':
			sort_elfs=1;
			break;
		case 's':
			sort_syms=1;
			break;
		case 256:
			use_regex=1;
			int r;
			if ((r = regcomp(&regex, optarg, REG_EXTENDED|REG_NOSUB)) != 0) {
				char *msg = NULL;
				size_t need = regerror(r, &regex, NULL, 0);
				if (need > 0) {
					msg = (char *)malloc(need);
					if (msg != NULL) {
						regerror(r, &regex, msg, need);
					}
				}
				if (msg != NULL) {
					fprintf(stderr,
						PROGNAME ": ERROR: regex compilation failure: %s.\n",
						msg);
				} else {
					fprintf(stderr,
						PROGNAME ": ERROR: regex compilation failure.\n");
				}
				return 1;
			}
			break;
		case 'h':
			usage();
			break;
		default:
			break;
		}
	}
	if (argc < 2) {
		fprintf(stderr, "Usage: resolved-symbols [--resolved|--unresolved] [--sort-elfs]\n"
		                "       [--sort-syms] [--grep=REGEX] <pid> [<pid> ...]\n");
		return 1;
	}
	for (int i=optind; i < argc; ++i) {
		int status, pid;
		library_t *libs = NULL;
		unsigned libs_cnt = 0;
		pid = atoi(argv[i]);
		printf("PID: %d%s\n", pid, check_environ(pid));
		getlibs(pid, &libs, &libs_cnt);
		if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
			fprintf(stderr, PROGNAME ": [%d]: ptrace warning: unable to attach: %s\n",
					pid, strerror(errno));
			goto next;
		}
		if (wait(&status) == -1) {
			fprintf(stderr, PROGNAME ": [%d]: ptrace warning: wait() failed.\n",
					pid);
			goto next;
		}
		if (!WIFSTOPPED(status)) {
			fprintf(stderr, PROGNAME ": [%d]: ptrace warning: process did not stop at signal delivery.\n",
					pid);
			goto next;
		}
		for (unsigned i=0; i < libs_cnt; ++i) {
			for (unsigned j=0; j < libs[i].pltsyms_cnt; ++j) {
				libs[i].pltsyms[j].resolved =
					pltsym_resolved(&libs[i], j, pid);
			}
		}
		if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
			fprintf(stderr, PROGNAME ": [%d]: warning: ptrace: unable to detach: %s\n",
					pid, strerror(errno));
		}
		if (sort_elfs && libs_cnt > 1) {
			qsort(libs, libs_cnt, sizeof(library_t), libname_cmp);
		}
		if (sort_syms && libs_cnt > 1) {
			for (unsigned i=0; i < libs_cnt; ++i) {
				qsort(libs[i].pltsyms, libs[i].pltsyms_cnt,
					sizeof(pltsym_t), symname_cmp);
			}
		}
		for (unsigned i=0; i < libs_cnt; ++i) {
			unsigned long resolved=0, unresolved=0;
			for (unsigned j=0; j < libs[i].pltsyms_cnt; ++j) {
				if (libs[i].pltsyms[j].resolved) ++resolved;
				else                             ++unresolved;
			}
			printf("%s [Resolved: %lu, Unresolved: %lu]\n",
					libs[i].path,
					resolved, unresolved);
			for (unsigned c=0, j=0; j < libs[i].pltsyms_cnt; ++j) {
				unsigned r = libs[i].pltsyms[j].resolved;
				char *sym = libs[i].pltsyms[j].symbol;
				if (resolved_only && r==0) continue;
				if (unresolved_only && r==1) continue;
				if (use_regex &&
				    regexec(&regex, sym, 0, NULL, 0) != 0)
					continue;
				printf("%10d. [Resolved: %c] %s\n",
					c++, r ? 'Y' : 'N', sym);
			}
			fflush(stdout);
		}
next:
		for (unsigned i=0; i < libs_cnt; ++i) {
			free(libs[i].path);
			free(libs[i].vmas);
			for (unsigned j=0; j < libs[i].pltsyms_cnt; ++j)
				free(libs[i].pltsyms[j].symbol);
			free(libs[i].pltsyms);
		}
		free(libs);
	}
	if (use_regex) regfree(&regex);
}
