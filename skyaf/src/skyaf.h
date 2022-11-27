// Author: i0gan
// Github: https://github.com/i0gan/pwn_waf
// Pwn Waf for AWD CTF

# pragma once
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <error.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include "logger.h"

#define CATCH   0x01
#define I0GAN   0x02
#define FORWARD 0x03
#define FORWARD_MULTI 0x04

// just used log method
#define OPEN   0x01
#define CLOSE   0x02

#define LISTEN_ELF   LOG_PATH "/pwn"       // trace elf file
#define HOSTS_FILE   LOG_PATH "/hosts.txt" // hosts file for forward
#define HOSTS_ATTACK_INDEX_FILE   LOG_PATH "/.multi_index" // hosts attack index file for FORWARD_MULTI mode

#define SEND_BUF_SIZE 0x2000
#define RECV_BUF_SIZE 0x2000

#ifndef LOG_METHOD
#define LOG_METHOD OPEN
#endif

enum log_state {
    LOG_NONE_,
    LOG_READ_,
    LOG_WRITE_
};

// error code avoid zombie parent process
#define ERROR_EXIT(x)  \
    x == 0xb7f

// judge is standard io
#define STANDARD_IO(x) \
    x == 0 ||          \
    x == 1 || \
    x == 2

// dangerous syscall
#define DANGEROUS_SYSCALL(x)  \
	x == __NR_open  || \
    x == __NR_clone || \
	x == __NR_execve


int readn(int fd, char *buf, int length);
int writen(int fd, void *buffer, size_t length);
void waf_write_logo();
void waf_write_hex_log();
void waf_log_open();
int connect_server(char* ip, ushort port);
void waf_init();
int waf_run();
void get_flag();
