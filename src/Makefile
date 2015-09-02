CFLAGS= -std=gnu99
DEPS = endian.h 
LIBS=$(LDFLAGS) -L. -lpcap -ljson-c -lssl -lcurl
OBJ = rascal.o radiotap.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $<

rascal: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -rf *.o 
	rm -rf rascal
