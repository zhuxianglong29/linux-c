#ifndef _SYS_UTIL_H_
#define _SYS_UTIL_H_

#include "common.h"

int tcp_client(unsigned short port);

int tcp_server(const char *host,unsigned short port);//绑定监听封装函数
        
int getlocalip(char *ip);//读取本地IP 
void activate_nonblock(int fd);//将文件描述符转换为非阻塞模式
void deactivate_nonblock(int fd);//去掉非阻塞变为阻塞

int read_timeout(int fd, unsigned int wait_seconds);
int write_timeout(int fd, unsigned int wait_seconds);
int accept_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds);
int connect_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds);

ssize_t readn(int fd, void *buf, size_t count);
ssize_t writen(int fd, const void *buf, size_t count);
ssize_t recv_peek(int sockfd, void *buf, size_t len);
ssize_t readline(int sockfd, void *buf, size_t maxline);//按行读取

void send_fd(int sock_fd, int fd);
int recv_fd(const int sock_fd);

const char* statbuf_get_perms(struct stat *sbuf);
const char* statbuf_get_date(struct stat *sbuf);

int lock_file_read(int fd);
int lock_file_write(int fd);
int unlock_file(int fd);

long get_time_sec(void);
long get_time_usec(void);
void nano_sleep(double seconds);

void activate_oobinline(int fd);
void activate_sigurg(int fd);

#endif
