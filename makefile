CXX=g++
CC=gcc
CFLAGS=-Wall -Wextra -Werror -pedantic -fsanitize=address -g
LDFLAGS=-fsanitize=address -static-libasan
SRCS=sha256.cpp
OBJS=$(SRCS:.cpp=.o)
NAME=kry

all: link clean

clean:
	rm -f *.o

clean_all: clean
	rm -f $(NAME)

link: compile
	$(CXX) $(OBJS) -o $(NAME) $(LDFLAGS)

compile:
	$(CXX) $(CFLAGS) $(SRCS) -c

