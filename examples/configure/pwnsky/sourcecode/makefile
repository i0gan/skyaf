TARGET = pwnsky
CFLAGS = -fstack-protector-all -fPIC -std=c99 -lseccomp /usr/lib/liblua.so.5.3
OBJ = main.o
RM = rm -f
CC = gcc
LUA = lua.bin

$(TARGET) : $(OBJ) $(LUA)
	$(CC) -o $@ $< $(CFLAGS)

$(OBJ) :%.o:%.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(LUA):main.lua
	luac5.3 -o $@ $<

clean:
	$(RM) $(OBJ) $(TARGET) $(LUA)
