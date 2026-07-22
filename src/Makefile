CFLAGS = -W -Wall -fPIC -Wno-pointer-to-int-cast -Wunused-parameter -O3 -march=native -mclwb -mavx512f #-pg #

#CFLAGS = -W -Wall -fPIC -g -DDEBUG -Wno-pointer-to-int-cast

LDFLAGS = -ldl -lpthread  -lm # -lpmem
TARGET = mgsp.so

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))

all : $(TARGET)

$(TARGET) : $(OBJECTS)
	$(CC) -shared -o $@ $^ $(LDFLAGS) libpmem2.a

#libpmem2.a

clean :
	$(RM) $(OBJECTS) $(TARGET)
