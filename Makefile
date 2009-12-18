all: pipi

pipi: main.o base64.o md5.o aes.o
	cc $^ -o $@ -lm
clean:
	rm -f main.o aes.o base64.o md5.o *~
