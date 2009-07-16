all: pmaps resolved-symbols

pmaps: pmaps.c Makefile
	gcc $< -o $@ -O2 -g -Wall -Wextra -std=c99

resolved-symbols: resolved-symbols.c Makefile
	gcc $< -o $@ -O2 -g -Wall -Wextra -std=c99

clean:
	rm -f *~ pmaps resolved-symbols

.PHONY: all clean
