CC = gcc
CFLAGS = -Wall -g -D_FILE_OFFSET_BITS=64
LIBS = `pkg-config fuse --cflags --libs` -lcrypto

TARGET = mirror_fs
SRC = mirror_fs.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)