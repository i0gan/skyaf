# Author: i0gan
# Date  : 2020-12-15

GCC    := gcc
CFLAGS := -O2 --static
RM     := rm -rf

# configure
# log path
LOG_METHOD  := OPEN
LOG_PATH    := ./skyaf_data
SKY_TOKEN_LOCK_FILE := ./skyaf_token.lock

# src
HEX_SRC      := src/hex.c
LOGGER_SRC   := src/logger.c
WAF_SRC      := src/skyaf.c

all : skyaf

clean :
	$(RM) skyaf $(LOG_PATH)

skyaf : 
	@mkdir -p $(LOG_PATH)
	$(GCC) $(CFLAGS) $(WAF_SRC) $(LOGGER_SRC) -DLOG_METHOD=$(LOG_METHOD) -DLOG_PATH=\"$(LOG_PATH)\" -DSKY_TOKEN_LOCK_FILE=\"$(SKY_TOKEN_LOCK_FILE)\" -o $@
