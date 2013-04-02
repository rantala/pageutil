/* This application lists per process memory mappings, and shows for each page
 * some details that the kernel exposes via various /proc interfaces.
 *
 * Copyright (C) 2009, 2013 Tommi Rantala <tt.rantala@gmail.com>
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

#include <regex.h>
#include <getopt.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <linux/kernel-page-flags.h>

#ifndef KPF_THP
#define KPF_THP			22
#endif

#ifndef KPF_RESERVED
#define KPF_RESERVED		32
#endif

#ifndef KPF_MLOCKED
#define KPF_MLOCKED		33
#endif

#ifndef KPF_MAPPEDTODISK
#define KPF_MAPPEDTODISK	34
#endif

#ifndef KPF_PRIVATE
#define KPF_PRIVATE		35
#endif

#ifndef KPF_PRIVATE_2
#define KPF_PRIVATE_2		36
#endif

#ifndef KPF_OWNER_PRIVATE
#define KPF_OWNER_PRIVATE	37
#endif

#ifndef KPF_ARCH
#define KPF_ARCH		38
#endif

#ifndef KPF_UNCACHED
#define KPF_UNCACHED		39
#endif

static off_t
x_lseek(int fd, off_t offset, int whence)
{
	off_t off = lseek(fd, offset, whence);
	if (off == (off_t)-1) {
		if (errno) {
			fprintf(stderr, "ERROR: lseek() failed: %s\n",
				strerror(errno));
		} else {
			fprintf(stderr, "ERROR: lseek() failed.\n");
		}
		exit(1);
	}
	return off;
}

static ssize_t
x_read(int fd, void *buf, size_t count)
{
	ssize_t got = read(fd, buf, count);
	if (got < 0 || (size_t)got != count) {
		if (errno) {
			fprintf(stderr,
				"ERROR: read() failure, tried to read %zu bytes, got %zd: %s\n",
				count, got, strerror(errno));
		} else {
			fprintf(stderr,
				"ERROR: read() failure, tried to read %zu bytes, got %zd.\n",
				count, got);
		}
		exit(1);
	}
	return got;
}

static unsigned long
min_ul(unsigned long a, unsigned long b)
{
	return b < a ? b : a;
}

#define BSIZE 1024
static uint64_t pagemap[BSIZE];
static uint64_t pageflags[BSIZE];
static uint64_t pagecount[BSIZE];
static unsigned long pagesize = 0;

static const char *
proc_fn(int pid, const char *procfile)
{
	static char buf[64];
	(void) snprintf(buf, sizeof(buf), "/proc/%d/%s", pid, procfile);
	buf[sizeof(buf)-1] = 0;
	return buf;
}

static const char *const flagname[] = {
	[KPF_LOCKED]               = "locked",
	[KPF_ERROR]                = "error",
	[KPF_REFERENCED]           = "referenced",
	[KPF_UPTODATE]             = "uptodate",
	[KPF_DIRTY]                = "dirty",
	[KPF_LRU]                  = "lru",
	[KPF_ACTIVE]               = "active",
	[KPF_SLAB]                 = "slab",
	[KPF_WRITEBACK]            = "writeback",
	[KPF_RECLAIM]              = "reclaim",
	[KPF_BUDDY]                = "buddy",
	[KPF_MMAP]                 = "mmap",
	[KPF_ANON]                 = "anon",
	[KPF_SWAPCACHE]            = "swapcache",
	[KPF_SWAPBACKED]           = "swapbacked",
	[KPF_COMPOUND_HEAD]        = "compound_head",
	[KPF_COMPOUND_TAIL]        = "compound_tail",
	[KPF_HUGE]                 = "huge",
	[KPF_UNEVICTABLE]          = "unevictable",
	[KPF_HWPOISON]             = "hwpoison",
	[KPF_NOPAGE]               = "nopage",
	[KPF_KSM]                  = "ksm",
	[KPF_THP]                  = "thp",
	[KPF_RESERVED]             = "reserved",
	[KPF_MLOCKED]              = "mlocked",
	[KPF_MAPPEDTODISK]         = "mappedtodisk",
	[KPF_PRIVATE]              = "private",
	[KPF_PRIVATE_2]            = "private_2",
	[KPF_OWNER_PRIVATE]        = "owner_private",
	[KPF_ARCH]                 = "arch",
	[KPF_UNCACHED]             = "uncached",
};

static const char *
flags2str(uint64_t flags)
{
	static char buf[128];
	uint64_t unknown_flags=0;
	unsigned i, n=0;
	buf[0]=0;
	for (i=0; flags; flags>>=1, ++i) {
		if (flags & 1) {
			if (i < sizeof(flagname)/sizeof(flagname[0]) && flagname[i]) {
				n += snprintf(buf+n, sizeof(buf)-n,
						"%s,", flagname[i]);
			} else {
				n += snprintf(buf+n, sizeof(buf)-n,
						"<bit %d>,", i);
				unknown_flags |= 1<<i;
			}
		}
	}
	if (n>0) buf[n-1]=0;
	if (unknown_flags) {
		static int once=0;
		if (!once) {
			fprintf(stderr,
			  "Warning: I did not understand all bits from kpageflags :(\n");
			once=1;
		}
	}
	return buf;
}

#define PMAP_PRESENT   (1ULL<<63)
#define PMAP_SWAPPED   (1ULL<<62)
#define PMAP_RESERVED  (1ULL<<61)
#define PMAP_PFN       ((~0ULL)>>9)
#define PMAP_PAGESHIFT ((~0ULL) & ~PMAP_PFN & ~PMAP_PRESENT & ~PMAP_SWAPPED & ~PMAP_RESERVED)
#define PMAP_SWAP_TYPE (0x1FULL)
#define PMAP_SWAP_OFF  (PMAP_PFN & ~PMAP_SWAP_TYPE)

static void
populate(int fd, uint64_t *dest, unsigned long nr)
{
	unsigned long i, pfn;
	uint64_t entry;
	for (i=0; i < nr; ++i) {
		entry = pagemap[i];
		if (PMAP_PRESENT & entry) {
			pfn = PMAP_PFN & entry;
			x_lseek(fd, pfn*sizeof(uint64_t), SEEK_SET);
			x_read(fd, dest+i, sizeof(uint64_t));
		} else {
			dest[i] = 0ULL;
		}
	}
}

typedef enum {
	SWAPPED_ONLY = 1,
	RESIDENT_ONLY = 2,
	STACK_ONLY = 4,
	HEAP_ONLY = 8,
} print_flags_t;

static void
pmaps(int pid, print_flags_t pflags, regex_t *regex, int fd_kflags, int fd_kcount)
{
	FILE *maps = NULL;
	int fd_p=-1;
	unsigned long start_addr, end_addr;
	char *line=0;
	size_t line_n=0;
	maps = fopen(proc_fn(pid, "maps"), "r");
	if (!maps) {
		fprintf(stderr,
			"ERROR: could not open /proc/%d/maps: %s\n",
			pid, strerror(errno));
		goto done;
	}
	fd_p = open(proc_fn(pid, "pagemap"), O_RDONLY);
	if (fd_p<0) {
		fprintf(stderr,
			"ERROR: could not open /proc/%d/pagemap: %s\n",
			pid, strerror(errno));
		goto done;
	}
	while (1) {
		int ret = getline(&line, &line_n, maps);
		if (ret == -1) {
			goto done;
		}
		if (pflags & STACK_ONLY) {
			if (strstr(line, "[stack]") == NULL)
				continue;
		} else if (pflags & HEAP_ONLY) {
			if (strstr(line, "[heap]") == NULL)
				continue;
		} else if (regex) {
			if (regexec(regex, line, 0, NULL, 0) != 0)
				continue;
		}
		if (sscanf(line, "%lx-%lx", &start_addr, &end_addr) != 2) {
			(void) fprintf(stderr,
			"ERROR: did not understand line from /proc/pid/maps. :(\n");
			goto done;
		}
		(void) printf("%s", line);
		unsigned long page_start = start_addr / pagesize;
		unsigned long page_end = end_addr / pagesize;
		x_lseek(fd_p, sizeof(uint64_t)*page_start, SEEK_SET);
		unsigned long nr_read = 0;
		unsigned long nr_read_total = 0;
		for (; page_start < page_end; page_start += BSIZE, nr_read_total += nr_read) {
			nr_read = min_ul(page_end-page_start, BSIZE);
			if (read(fd_p, pagemap, nr_read*sizeof(uint64_t))
					!= (ssize_t)(nr_read*sizeof(uint64_t))) {
				// Reading the /proc/pid/pagemap entry for
				// /proc/pid/maps [vsyscall] resulted in zero
				// byte reads. Let's just ignore such cases.
				continue;
			}
			populate(fd_kflags, pageflags, nr_read);
			populate(fd_kcount, pagecount, nr_read);
			for (unsigned i=0; i < nr_read; ++i) {
				if (PMAP_PRESENT&pagemap[i] && !(pflags & SWAPPED_ONLY)) {
					printf("    %#lx -> pfn:%#08llx count:%4llu flags:%s\n",
					       start_addr + (nr_read_total+i)*pagesize,
					       PMAP_PFN&pagemap[i],
					       (unsigned long long)pagecount[i],
					       flags2str(pageflags[i]));
				} else if (PMAP_SWAPPED&pagemap[i] && !(pflags & RESIDENT_ONLY)) {
					printf("   #%#lx -> swaptype:%#llx swapoff:%#08llx\n",
					       start_addr + (nr_read_total+i)*pagesize,
					       PMAP_SWAP_TYPE&pagemap[i],
					       (PMAP_SWAP_OFF&pagemap[i])>>5);
				} else if (!(pflags & (SWAPPED_ONLY|RESIDENT_ONLY))) {
					printf("   !%#lx\n",
					       start_addr + (nr_read_total+i)*pagesize);
				}
			}
		}
		if ((pflags & STACK_ONLY) || (pflags & HEAP_ONLY)) {
			goto done;
		}
	}
done:
	free(line);
	if (fd_p != -1) close(fd_p);
	if (maps != NULL) fclose(maps);
}

static const struct option long_options[] = {
	{"swapped", 0, 0, 'S'},
	{"resident", 0, 0, 'R'},
	{"stack", 0, 0, 256},
	{"heap", 0, 0, 257},
	{"grep", 1, 0, 258},
	{"help", 0, 0, 'h'},
	{0, 0, 0, 0}
};

static void
usage()
{
	fprintf(stderr,
		"pmaps: show kernel page state for each page mapped to given process.\n"
		"\n"
		"Usage:\n"
		"           pmaps <pid> [<pid> ...]\n"
		"\n"
		"           -R, --resident       Show only resident pages.\n"
		"           -S, --swapped        Show only pages that have been swapped\n"
		"                                out to disk.\n"
		"\n"
		"               --grep=REGEX     Only show mappings for lines from /proc/pid/maps\n"
		"                                that match the regular expression REGEX.\n"
		"               --stack          Show only pages for process stack, identified\n"
		"                                by [stack] in /proc/pid/maps.\n"
		"               --heap           Show only pages for process heap, identified\n"
		"                                by [heap] in /proc/pid/maps.\n"
	       );
}

int main(int argc, char **argv)
{
	int opt, fd_kflags, fd_kcount;
	print_flags_t pflags = 0;
	char *regstr = NULL;
	regex_t regex;
	while ((opt = getopt_long(argc, argv, "r:SRh",
			long_options, NULL)) != -1) {
		switch(opt) {
		case 'S':
			pflags |= SWAPPED_ONLY;
			break;
		case 'R':
			pflags |= RESIDENT_ONLY;
			break;
		case 256:
			pflags |= STACK_ONLY;
			break;
		case 257:
			pflags |= HEAP_ONLY;
			break;
		case 258:
			regstr = optarg;
			break;
		case 'h':
			usage();
			/* fall through */
		default:
			break;
		}
	}
	if ((pflags & SWAPPED_ONLY) && (pflags & RESIDENT_ONLY)) {
		fprintf(stderr, "pmaps: please define either -S or -R.\n");
		return 1;
	}
	if ((pflags & STACK_ONLY) && (pflags & HEAP_ONLY)) {
		fprintf(stderr, "pmaps: please define either --stack or --heap.\n");
	}
	if (regstr && ((pflags & STACK_ONLY) || (pflags & HEAP_ONLY))) {
		fprintf(stderr, "pmaps: please define either --grep, --stack or --heap.\n");
	}
	if (optind >= argc) {
		fprintf(stderr, "Usage: pmaps [--resident|--swapped] [--grep=REGEX|--stack|--heap] <pid> [<pid> ...]\n");
		return 1;
	}
	pagesize = sysconf(_SC_PAGESIZE);
	if (regstr) {
		int comp;
		if ((comp = regcomp(&regex, regstr, REG_EXTENDED|REG_NOSUB)) != 0) {
			char *err = NULL;
			size_t errlen = regerror(comp, &regex, NULL, 0);
			if ((err = malloc(errlen)) != NULL) {
				regerror(comp, &regex, err, errlen);
			}
			fprintf(stderr, "Regex compilation failure: %s\n",
					err ? err : "(unspecified)");
			free(err);
			return 1;
		}
	}
	fd_kflags = open("/proc/kpageflags", O_RDONLY);
	if (fd_kflags<0) {
		perror("ERROR: could not open /proc/kpageflags");
		return 1;
	}
	fd_kcount = open("/proc/kpagecount", O_RDONLY);
	if (fd_kcount<0) {
		perror("ERROR: could not open /proc/kpagecount");
		return 1;
	}
	for (int i=optind; i < argc; ++i) {
		int pid = atoi(argv[i]);
		const char *note1 = "", *note2 = "";
		if (pflags & RESIDENT_ONLY) note1 = " [resident-pages-only]";
		if (pflags & SWAPPED_ONLY)  note1 = " [swapped-pages-only]";
		if (pflags & STACK_ONLY)    note2 = " [stack-only]";
		if (pflags & HEAP_ONLY)     note2 = " [heap-only]";
		printf("PID: %d%s%s\n", pid, note1, note2);
		pmaps(pid, pflags, regstr ? &regex : NULL, fd_kflags, fd_kcount);
	}
	if (regstr) regfree(&regex);
	close(fd_kflags);
	close(fd_kcount);
	return 0;
}
