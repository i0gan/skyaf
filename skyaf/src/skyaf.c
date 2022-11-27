#include "skyaf.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
// 提示说明：
// 你需要通过程序漏洞去获取远程 /sky_token 文件内容，释放赛题后通过sky_token获取flag。
// 请严格按照报名要求填写队伍名称以及选手id或名字


const char logo_str[]      = "// skyaf github: https://github.com/i0gan/skyaf \n";
const char read_str[]      = "\n<-------------------- read ------------------>\n";
const char write_str[]     = "\n<-------------------- write ----------------->\n";

char *hosts_str1_buf = NULL;
char *hosts_str2_buf = NULL;
enum log_state waf_log_state = LOG_NONE_;

char chall_sky_token_path[0x100];
char chall_sky_token[0x100];
char chall_flag[0x100];
char chall_ip[0x80];
ushort chall_port;

int  waf_write_times = 0;
int  waf_read_times  = 0;
char send_buf[SEND_BUF_SIZE];
char recv_buf[SEND_BUF_SIZE];

void set_fd_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL,flags);
}

int readn(int fd, char *buf, int length) {
    int read_sum = 0;
    while(read_sum < length) {
        int read_size = read(fd, buf + read_sum, length - read_sum);
        if(read_size <= 0)
        break;
        read_sum += read_size;
    }
    return read_sum;
}

int writen(int fd, void *buffer, size_t length) {
    int write_left = length;
    int write_len = 0;
    int write_sum = 0;
    char *write_ptr = (char *)buffer;
    while(write_left > 0) {
        if((write_len = write(fd, write_ptr, write_left)) < 0) {
            if(errno == EINTR)
                continue;
            else if(errno == EAGAIN) {
                return write_sum;
            }else {
                return -1;
            }
        }
        write_sum += write_len;
        write_left -= write_len;
        write_ptr += write_len;
    }
    return write_sum;
}

void waf_write_logo() {
#if LOG_METHOD == CLOSE
    return;
#endif

    char time_str[128] = {0};
    struct timeval tv;
    time_t time;
    gettimeofday(&tv, NULL);
    time = tv.tv_sec;
    struct tm *p_time = localtime(&time);
    strftime(time_str, 128, "// Date: %Y-%m-%d %H:%M:%S\n", p_time);
    logger_write(time_str, strlen(time_str));
    logger_write(logo_str, sizeof(logo_str) - 1);
}

void waf_write_hex_log() {
#if LOG_METHOD == CLOSE
    return;
#endif
    if(logger_size() == 0) return;
    char str[0x60] = {0};
    if(waf_log_state == LOG_WRITE_) {
        snprintf(str, 0x60, "\nw_%d = \"", waf_write_times);
        logger_write(str, strlen(str));
        waf_write_times ++;
    }else {
        snprintf(str, 0x60, "\nr_%d = \"", waf_read_times);
        logger_write(str, strlen(str));
        waf_read_times ++;
    }
    logger_write_buf();
    logger_write("\"\n", 2);
}

void waf_log_open() {
#if LOG_METHOD == CLOSE
    return;
#endif
    char time_str[0x20] = {0};
    char file_name[0x100] = {0};
    struct timeval tv;
    time_t time_;
    gettimeofday(&tv, NULL);
    time_ = tv.tv_sec;
    struct tm *p_time = localtime(&time_);
    strftime(time_str, 128, "%H_%M_%S", p_time);
    snprintf(file_name, 0x100, "%s/%s_%lx%s", LOG_PATH, time_str, tv.tv_usec, ".log");
    if(logger_open(file_name) == 0) {
        printf("Open log [%s] file failed!\n", file_name);
        exit(-1);
    }
}


int connect_server(char* ip, ushort port) {    
    struct sockaddr_in server_addr;
    int server_fd = -1;
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(server_fd == -1) {
        perror("socket");
        return -1;
    }
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if(inet_aton(ip, (struct in_addr*)&server_addr.sin_addr.s_addr) == 0){
        perror("ip error");
        return -1;
    }
    if(connect(server_fd,(struct sockaddr*)&server_addr,sizeof(struct sockaddr)) == -1){
        perror("connect:");
        return -1;
    }
    return server_fd;
}

int block_read(int fd, char *buf, int length, int ms) {
    // 等待 60 秒输入名称
    int idx = 0;
    int readed_len = 0;
    for(int times = 0; times < ms; times++) {
        int read_len = read(0, &buf[idx], 0x100);
        usleep(1000); // 一毫秒
        if(read_len < 0) { // timeout
            continue;
        } else if(read_len == 0) {
            break;
        } else if(read_len == 1) {
            if(buf[idx] == '\n') {
                buf[idx] = '\0';
                break;
            }
            idx += 1;
            readed_len += 1;
        } else if(read_len > 0){
            idx += read_len;
            readed_len += read_len;
            break;
        }
    }
    
    return readed_len;
}

int waf_run() {
    fd_set read_fds, test_fds;
    int client_read_fd = 0;
    int client_write_fd = 1;
    int client_error_fd = 2;
    int is_released = 0;

    int server_fd = connect_server(chall_ip, chall_port);

    FD_ZERO(&read_fds);
    FD_ZERO(&test_fds);

    FD_SET(server_fd, &read_fds);
    FD_SET(client_read_fd, &read_fds);  // standard input fd
    FD_SET(client_write_fd, &read_fds); // standard write fd
    FD_SET(client_error_fd, &read_fds); // standard error fd

    set_fd_nonblock(server_fd);
    set_fd_nonblock(client_read_fd);
    set_fd_nonblock(client_write_fd);
    set_fd_nonblock(client_error_fd);

    while(1) {
        enum log_state log_state_ = LOG_NONE_;
        test_fds = read_fds;
        int result = select(FD_SETSIZE, &test_fds, (fd_set *)0, (fd_set *)0, (struct timeval *) 0);
        if(result < 1) {
            perror("select");
            return -1;
        }
        for(int fd = 0; fd < FD_SETSIZE; fd ++) {
            if(FD_ISSET(fd, &test_fds)) {
                int write_size = -1;
                int read_size = -1;
                if(fd == server_fd) { // 赛题端
                    write_size = read(server_fd, recv_buf, RECV_BUF_SIZE);
                    writen(client_write_fd, recv_buf, write_size);
                }else if(fd == client_read_fd) {  // 标准输入端
                    read_size = read(client_read_fd, send_buf, SEND_BUF_SIZE);
                    if(is_released == 1) {
                        logger_write_str("logger: chall env released");
                        //writen(client_write_fd, send_buf, strlen(send_buf));
                        if(!strncmp(send_buf, chall_sky_token, strlen(chall_sky_token))) {
                            char team_name[0x100];
                            char user_name[0x100];
                            int read_len = 0;
                            logger_write_str("\nlogger: sky_token_is_right\n");
                            print_str("\033[31;5mYour team name:\033[0m\n");
                            // 等待 60 秒输入名称
                            read_len = block_read(0, team_name, 0x100, 60 * 1000);
                            logger_write_str("team_name: "); 
                            logger_write(team_name, read_len);
                            logger_write_str("\n"); 
    
                            print_str("\033[31;5mYour id name:\033[0m\n");
                            read_len = block_read(0, user_name, 0x100, 60 * 1000);
                            logger_write_str("user_name: "); 
                            logger_write(user_name, read_len);
                            logger_write_str("\n"); 

                            get_flag();
                        }else {
                            char *str = "\033[31;1msky_token is wrong!\n\033[0m";
                            writen(client_write_fd, str, strlen(str));
                            logger_write_str("\nlogger: sky_token_is_wrong\n");
                        }
                        return 0;
                    }else {
                        writen(server_fd, send_buf, read_size);
                    }
                }else if(fd == client_write_fd) { // 标准输出端
                    read_size = read(client_write_fd, send_buf, SEND_BUF_SIZE);
                    writen(server_fd, send_buf, read_size);
                }else if(fd == client_error_fd) { // 标准输出错误端
                    read_size = read(client_error_fd, send_buf, SEND_BUF_SIZE);
                    writen(server_fd, send_buf, read_size);
				}

                // 赛环境断开连接
                if(write_size == 0) {

                    //char *str = "Chellenge env released";
                    //writen(client_write_fd, str, strlen(str));

                    char *str = "\033[31;5mYour sky_token:\033[0m";
                    writen(client_write_fd, str, strlen(str));

                    FD_CLR(server_fd, &read_fds);
                    close(server_fd);
                    free(hosts_str1_buf);
                    free(hosts_str2_buf);
                    is_released = 1;
                }

                // handle disconnect
                if(read_size == 0) {
                    // 客户端断开连接
                    close(server_fd);
                    free(hosts_str1_buf);
                    free(hosts_str2_buf);
                    return -1;
                }

                // 日志打印
                if(read_size > 0 || write_size > 0) {
                    if(read_size > 0)
                        log_state_ = LOG_READ_;
                    else
                        log_state_ = LOG_WRITE_;
                    if(waf_log_state != log_state_) {
                        // when state changed, then write data to log
                        waf_write_hex_log(); // write_last_log_buf
                        if(log_state_ == LOG_READ_) {
                            logger_write(read_str, sizeof(read_str) - 1);
                        } else {
                            logger_write(write_str, sizeof(write_str) - 1);
                        }
                        waf_log_state = log_state_;
                    }
                    if(read_size > 0) {
                        logger_append_hex(send_buf, read_size);
                        logger_write(send_buf, read_size);
                    } else {
                        logger_append_hex(recv_buf, write_size);
                        logger_write(recv_buf, write_size);
                    }
                }
            }
        }
    }
}

void waf_init() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
#if LOG_METHOD == OPEN
	logger_init(LOG_PATH);
    waf_log_open();
    waf_write_logo();
#endif

}

void get_flag() {
    char flag[0x101] = {0};
    strncat(flag, "\033[32;2mHere is your flag: ", 0x100);
    strncat(flag, chall_flag, 0x100);
    strncat(flag, "\033[0m\n", 0x100);
    writen(1, flag, strlen(flag));
}

void print_str(const char *str) {
    writen(1, str, strlen(str));
}

int init_chall_env() {
    long int rand_num = 0;
    char token[0x100];

    // 有锁文件，说明有人连接了，没有锁则生成一个
    if((access(SKY_TOKEN_LOCK_FILE,F_OK)) != -1) {
        int fd = open(chall_sky_token_path, O_RDWR | O_CREAT, 0755);
        if(fd == -1) {
            perror("open1");
            return -1;
        }
        read(fd, token, 16);
        memcpy(chall_sky_token, token, 16);
        close(fd);
    } else {
        // 加锁
        int fd = open(SKY_TOKEN_LOCK_FILE, O_WRONLY | O_CREAT, 0755);
        if(fd == -1) {
            perror("open2");
            return -1;
        }
        close(fd);

        // 重新生成token
        time_t t = time(0);
        srand(t);
        rand_num = rand();
        rand_num <<= 32;
        rand_num += rand();
        snprintf(chall_sky_token, 0x80, "%016llX", rand_num);
        fd = open(chall_sky_token_path, O_WRONLY | O_CREAT, 0755);
        if(fd == -1) {
            perror("open3");
            return -1;
        }
        write(fd, chall_sky_token, 16);
        close(fd);
    }
}

int main(int argc, char *argv[]) {
    //puts("\033[32;2mskyaf 1.0 防作弊监测系统\nskyctf.com \033[0m");
    // waf ip port sky_token_path flag
    // skyctf application firewall
    if(argc < 4) {
        puts("skyaf [ip] [port] [sky_token_path] {flag}");
        return -1;
    }
    strcpy(chall_ip, argv[1]);
    chall_port = atoi(argv[2]);
    strcpy(chall_sky_token_path, argv[3]);
    //puts("\033[32;2m赛题初始化中...\033[0m");
    if(argc > 4) {
        strcpy(chall_flag, argv[4]);
    }else {
        strcpy(chall_flag, "flag{not_initianized!}");
    }

    waf_init();
    init_chall_env();

    
    waf_run();

    waf_write_hex_log();
	logger_close();

    // 删除锁
    remove(SKY_TOKEN_LOCK_FILE);
    return 0;
}
