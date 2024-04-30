CXX=g++
CFLAGS=-Wall -Wextra -Werror -pedantic -fsanitize=leak -fsanitize=address -g
LDFLAGS=-fsanitize=address -fsanitize=leak -static-libasan
SRCS=sha256.cpp mac.cpp main.cpp
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

