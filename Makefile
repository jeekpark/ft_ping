
NAME := ft_ping
CC := cc
CFLAGS := -Wall -Wextra -Werror

INCS := ./

SRCS := main.c utils.c

OBJS := $(SRCS:.c=.o)

%.o: %.c
	$(CC) $(CFLAGS) -I$(INCS) -c -o $@ $<


all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(NAME)

re:
	$(MAKE) fclean
	$(MAKE) all


.PHONY: all clean fclean re