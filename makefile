all: myPing_1

%: %.c
	gcc -Wall $< -o $@ -lpthread


