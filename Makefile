CC       = gcc
CFLAGS   = -O2 -march=native -flto -Wall -Wextra -Werror -std=c11
CFLAGS  += -D_GNU_SOURCE
LDFLAGS  = -flto

# Debug build: make DEBUG=1
ifdef DEBUG
CFLAGS  += -g -DDEBUG -O0
CFLAGS  := $(filter-out -Werror,$(CFLAGS))
endif

# Source files
SRC_DIR  = src
VEND_DIR = vendor/cJSON

SRCS     = $(SRC_DIR)/main.c     \
           $(SRC_DIR)/config.c   \
           $(SRC_DIR)/packet.c   \
           $(SRC_DIR)/raw_socket.c \
           $(SRC_DIR)/session.c  \
           $(SRC_DIR)/pool.c     \
           $(SRC_DIR)/client.c   \
           $(SRC_DIR)/server.c   \
           $(VEND_DIR)/cJSON.c

OBJS     = $(SRCS:.c=.o)
TARGET   = injspoof

.PHONY: all clean debug install

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(VEND_DIR)/%.o: $(VEND_DIR)/%.c
	$(CC) $(CFLAGS) -Wno-unused-parameter -c -o $@ $<

debug:
	$(MAKE) DEBUG=1

clean:
	rm -f $(OBJS) $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/
	@echo "Installed. You may need to run: sudo setcap cap_net_raw+ep /usr/local/bin/$(TARGET)"
