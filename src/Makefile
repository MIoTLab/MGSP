CFLAGS = -W -Wall -fPIC -Wno-pointer-to-int-cast -Wunused-parameter -O3 

#CFLAGS = -W -Wall -fPIC -g -DDEBUG -Wno-pointer-to-int-cast

LDFLAGS = -ldl -lpthread -lpmem -lm
TARGET = mgsp.so

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))

all : $(TARGET)

$(TARGET) : $(OBJECTS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

clean :
	$(RM) $(OBJECTS) $(TARGET)
 