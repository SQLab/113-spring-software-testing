CC=gcc

.PHONY: all
all: bss_overflow_asan

bss_overflow_asan: bss_overflow.c libantiasan.so
	$(CC) -fsanitize=address -Og -g -o $@ $< -lantiasan -L.

libantiasan.so: antiasan.c
	$(CC) -g -fPIC -c antiasan.c
	$(CC) -shared antiasan.o -o libantiasan.so

.PHINY: run
run:
	LD_LIBRARY_PATH=. ./bss_overflow_asan

.PHONY: clean
clean:
	rm bss_overflow_asan antiasan.o libantiasan.so
