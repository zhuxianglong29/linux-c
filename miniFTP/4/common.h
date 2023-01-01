#ifndef _COMMON_H_
#define _COMMON_H_

#include <unistd.h> //unix环境编程
#include <sys/types.h> //基本系统数据类型
#include <fcntl.h>  //根据文件描述词来操作文件的特性
#include <errno.h>  //错误处理
#include <sys/socket.h> //套机制
#include <netinet/in.h> //地址
#include <arpa/inet.h>	//将IPv4和IPv6的地址从binary向text形式转化
#include <netdb.h> //网络编程，获得IP需要
#include <pwd.h> //用户uid,gid问题
#include <shadow.h> //getspnam
#include <crypt.h>
#include <signal.h>
#include <sys/syscall.h>

#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/time.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/capability.h>//进程权限
#include <sys/sendfile.h>
#include <sys/wait.h>

#include <stdlib.h> //标准C编程
#include <stdio.h>
#include <string.h>
#include <ctype.h>  //isspace()




#define ERR_EXIT(m) \
        do \
        { \
                perror(m); \
                exit(EXIT_FAILURE); \
        } while(0)

#define MAX_COMMAND_LINE 1024
#define MAX_COMMAND 32
#define MAX_ARG 1024
#define MINIFTP_CONF "miniftpd.conf"

#endif
