all: myPing

%: %.c
	gcc -Wall $< -o $@ -lpthread


