all:
	mkdir -p bin
	c99 -pedantic -Wall src/main.c -o bin/duhttp
