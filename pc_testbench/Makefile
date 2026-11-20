CC = gcc
CFLAGS = -Wall -Wextra -O2 -I../algorithms

# Our source files
SRCS = main.c ../algorithms/blake2s.c
OBJS = $(SRCS:.c=.o)
TARGET = testbench

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
