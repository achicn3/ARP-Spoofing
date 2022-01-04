CC:=gcc
exe:=main
obj:=main.o arp.o

all:$(obj)
	$(CC) -o $(exe) $(obj)  
%.o:%.c
	$(CC) -c $^ -o $@

clean:
	rm -rf *.o main

