all:
	mkdir -p bin
	c99 -Wall -pedantic src/main.c -o bin/duhttp
