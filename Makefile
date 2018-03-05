CFLAGS=-std=c99 -Wall -Wextra -Werror

libqipcrtr4msmipc.so: main.c
	gcc $(CFLAGS) -shared $< -o $@
