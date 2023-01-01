#include "ftpproto.h"
#include "common.h"
#include "sysutil.h"
#include "str.h"
#include "ftpcodes.h"
#include "tunable.h"

void ftp_reply(session_t *sess,int status,const char *text);
void ftp_lreply(session_t *sess,int status,const char *text);

int list_common(session_t *sess);
int get_transfer_fd(session_t *sess);
int pasv_active(session_t *sess);
int port_active(session_t *sess);
int get_localip(const char * eth_name, char *local_ip_addr);

static void do_user(session_t *sess);
static void do_pass(session_t *sess);
static void do_cwd(session_t *sess);
static void do_cdup(session_t *sess);
static void do_quit(session_t *sess);
static void do_port(session_t *sess);
static void do_pasv(session_t *sess);
static void do_type(session_t *sess);
static void do_stru(session_t *sess);
static void do_mode(session_t *sess);
static void do_retr(session_t *sess);
static void do_stor(session_t *sess);
static void do_appe(session_t *sess);
static void do_list(session_t *sess);
static void do_nlst(session_t *sess);
static void do_rest(session_t *sess);
static void do_abor(session_t *sess);
static void do_pwd(session_t *sess);
static void do_mkd(session_t *sess);
static void do_rmd(session_t *sess);
static void do_dele(session_t *sess);
static void do_rnfr(session_t *sess);
static void do_rnto(session_t *sess);
static void do_site(session_t *sess);
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
static void do_size(session_t *sess);
static void do_stat(session_t *sess);
static void do_noop(session_t *sess);
static void do_help(session_t *sess);

typedef struct ftpcmd
{
	const char *cmd;
	void (*cmd_handler)(session_t *sess);
} ftpcmd_t;

static ftpcmd_t ctrl_cmds[] = {
	/* 访问控制命令 */
	{"USER",	do_user	},
	{"PASS",	do_pass	},
	{"CWD",		do_cwd	},
	{"XCWD",	do_cwd	},
	{"CDUP",	do_cdup	},
	{"XCUP",	do_cdup	},
	{"QUIT",	do_quit	},
	{"ACCT",	NULL	},
	{"SMNT",	NULL	},
	{"REIN",	NULL	},
	/* 传输参数命令 */
	{"PORT",	do_port	},
	{"PASV",	do_pasv	},
	{"TYPE",	do_type	},
	{"STRU",	do_stru	},
	{"MODE",	do_mode	},

	/* 服务命令 */
	{"RETR",	do_retr	},
	{"STOR",	do_stor	},
	{"APPE",	do_appe	},
	{"LIST",	do_list	},
	{"NLST",	do_nlst	},
	{"REST",	do_rest	},
	{"ABOR",	do_abor	},
	{"\377\364\377\362ABOR", do_abor},
	{"PWD",		do_pwd	},
	{"XPWD",	do_pwd	},
	{"MKD",		do_mkd	},
	{"XMKD",	do_mkd	},
	{"RMD",		do_rmd	},
	{"XRMD",	do_rmd	},
	{"DELE",	do_dele	},
	{"RNFR",	do_rnfr	},
	{"RNTO",	do_rnto	},
	{"SITE",	do_site	},
	{"SYST",	do_syst	},
	{"FEAT",	do_feat },
	{"SIZE",	do_size	},
	{"STAT",	do_stat	},
	{"NOOP",	do_noop	},
	{"HELP",	do_help	},
	{"STOU",	NULL	},
	{"ALLO",	NULL	}
};

void handle_child(session_t *sess)
{
	//writen(sess->ctrl_fd,"220 (miniftpd 0.1)\r\n",strlen("220 (miniftpd 0.1)\r\n"));//ftp_reply
	ftp_reply(sess,FTP_GREET,"miniftpd 0.1");
	int ret;
	while(1)
	{
		memset(sess->cmdline,0,sizeof(sess->cmdline));
		memset(sess->cmd,0,sizeof(sess->cmd));
		memset(sess->arg,0,sizeof(sess->arg));
		ret=readline(sess->ctrl_fd,sess->cmdline,MAX_COMMAND_LINE);
		if(ret==-1)
			ERR_EXIT("readline");
		else if(ret==0)//客户端断开连接
			exit(EXIT_SUCCESS);
		
		printf("cmdline=[%s]\n",sess->cmdline);
		//去除\r\n
		str_trim_crlf(sess->cmdline);
		printf("cmdline=[%s]\n",sess->cmdline);
		//解析FTP命令与参数
		str_split(sess->cmdline,sess->cmd,sess->arg,' ');
		printf("cmd=[%s] arg=[%s]\n",sess->cmd,sess->arg);
		//将命令转换为大写
		str_upper(sess->cmd);
		//处理FTP命令
		/*if else实现
		if(strcmp("USER",sess->cmd)==0)
		{
			do_user(sess);
		}
		else if(strcmp("PASS",sess->cmd)==0)
		{
			do_pass(sess);
		}
		*/
		
		int i;
		int size= sizeof(ctrl_cmds)/sizeof(ctrl_cmds[0]);
		for(i=0;i<size;i++)
		{
			if(strcmp(ctrl_cmds[i].cmd,sess->cmd)==0)
			{
				if(ctrl_cmds[i].cmd_handler !=NULL)
				{
					//printf("do it %s",ctrl_cmds[i]);
					ctrl_cmds[i].cmd_handler(sess);
				}
				else
				{
					ftp_reply(sess,FTP_COMMANDNOTIMPL,"Unimplement command.");
				}
				break;
			}
			
		}
		if(i==size)
			{
				ftp_reply(sess,FTP_BADCMD,"Unknow command.");
			}
	}
}

void ftp_reply(session_t *sess,int status,const char *text)
{
	char buf[1024]={0};
	sprintf(buf,"%d %s\r\n",status,text);
	writen(sess->ctrl_fd,buf,strlen(buf));
}

void ftp_lreply(session_t *sess,int status,const char *text)
{
	char buf[1024]={0};
	sprintf(buf,"%d-%s\r\n",status,text);
	writen(sess->ctrl_fd,buf,strlen(buf));
}

int list_common(session_t *sess)//获取文件列表信息相当ls -l
{
	DIR *dir=opendir(".");//opendir打开参数指定目录，并返回DIR形态目录流
	if(dir==NULL)
	{
		return 0;
	}
	struct dirent *dt;
	struct stat sbuf;
	while((dt=readdir(dir))!=NULL)//readdir读取目录流，返回dirent结构类型,man readdir查看
	{
		if(lstat(dt->d_name,&sbuf)<0)//lstat查看文件状态,返回-1为失败
		{
			continue;
		}
		if(dt->d_name[0]=='.')//成功后打印目录信息
			continue;
		/*stat 结构中哦的mode
		S_IFMT     0170000   bit mask for the file type bit field
           S_IFSOCK   0140000   socket
           S_IFLNK    0120000   symbolic link
           S_IFREG    0100000   regular file
           S_IFBLK    0060000   block device
           S_IFDIR    0040000   directory
           S_IFCHR    0020000   character device
           S_IFIFO    0010000   FIFO
		*/
		char perms[]="----------";//权限位10位
		perms[0]='?';
		mode_t mode=sbuf.st_mode;
		/*
		第1个字母：代表文件类型
		第2~4字母：代表用户的权限
		第5~7字母：代表用户组的权限
		第8~10字母：代表其他的用户的权限*/
		switch(mode &S_IFMT)
		{
			case S_IFREG:
				perms[0]='-';
				break;
			case S_IFDIR:
				perms[0] = 'd';
				break;
			case S_IFLNK:
				perms[0] = 'l';
				break;
			case S_IFIFO:
				perms[0] = 'p';
				break;
			case S_IFSOCK:
				perms[0] = 's';
				break;
			case S_IFCHR:
				perms[0] = 'c';
				break;
			case S_IFBLK:
				perms[0] = 'b';
				break;
		}
		//权限位获取
		if (mode & S_IRUSR)
		{
			perms[1] = 'r';
		}
		if (mode & S_IWUSR)
		{
			perms[2] = 'w';
		}
		if (mode & S_IXUSR)
		{
			perms[3] = 'x';
		}
		if (mode & S_IRGRP)
		{
			perms[4] = 'r';
		}
		if (mode & S_IWGRP)
		{
			perms[5] = 'w';
		}
		if (mode & S_IXGRP)
		{
			perms[6] = 'x';
		}
		if (mode & S_IROTH)
		{
			perms[7] = 'r';
		}
		if (mode & S_IWOTH)
		{
			perms[8] = 'w';
		}
		if (mode & S_IXOTH)
		{
			perms[9] = 'x';
		}
		if (mode & S_ISUID)
		{
			perms[3] = (perms[3] == 'x') ? 's' : 'S';
		}
		if (mode & S_ISGID)
		{
			perms[6] = (perms[6] == 'x') ? 's' : 'S';
		}
		if (mode & S_ISVTX)
		{
			perms[9] = (perms[9] == 'x') ? 't' : 'T';
		}
		char buf[1024]={0};
		int off = 0;
		off += sprintf(buf, "%s ", perms);
		off += sprintf(buf + off, " %3ld %-8d %-8d ", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid);//获取st_link连接数,uid,gid
		off += sprintf(buf + off, "%8lu ", (unsigned long)sbuf.st_size);//文件大小
		//两种日期man strftime 查看日期格式
		const char *p_date_format="%b %e %H:%H";
		struct timeval tv;
		gettimeofday(&tv,NULL);//获取系统时间
		long local_time=tv.tv_sec;
		if(sbuf.st_mtime>local_time||(local_time-sbuf.st_mtime)>60*60*24*182)
		{
			p_date_format="%b %e  %Y";
		}
		//格式化日期
		char datebuf[64] = {0};
		struct tm* p_tm = localtime(&local_time);
		strftime(datebuf, sizeof(datebuf), p_date_format, p_tm);
		off += sprintf(buf + off, "%s ", datebuf);
		if (S_ISLNK(sbuf.st_mode))//符合连接文件判定
		{
			char tmp[512] = {0};
			readlink(dt->d_name, tmp, sizeof(tmp));
			off += sprintf(buf + off, "%s -> %s\r\n", dt->d_name, tmp);//文件名
		}
		else
		{
			off += sprintf(buf + off, "%s\r\n", dt->d_name);
		}

		//printf("%s", buf);
		writen(sess->data_fd,buf,strlen(buf));	
	}
	closedir(dir);

	return 1;
}

int port_active(session_t *sess)
{
	if(sess->port_addr)
	{
		if(pasv_active(sess))
		{
			fprintf(stderr,"both port and pasv are active");
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	return 0;	
}

int pasv_active(session_t *sess)
{
	if(sess->pasv_listen_fd!=-1)
	{
		if(port_active(sess))
		{
			fprintf(stderr,"both port and pasv are active");
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	return 0;
}

int get_transfer_fd(session_t *sess)
{
	//检测是否收到PORT或PASV命令
	if(!port_active(sess)&&!pasv_active(sess))
	{
		ftp_reply(sess,FTP_BADSENDCONN,"Use PORT or PASV first.");
		return 0;
	}
	
	if(port_active(sess))
	{
		/*socket
		bind
		conn*/
		int fd=tcp_client(0);
		if(connect_timeout(fd,sess->port_addr,tunable_connect_timeout)<0)
		{
			close(fd);
			return 0;
		}
		sess->data_fd=fd;
	}
	if(pasv_active(sess))
	{
		int fd=accept_timeout(sess->pasv_listen_fd,NULL,tunable_accept_timeout);
		close(sess->pasv_listen_fd);
		if(fd==-1)
		{
			
			return 0;
		}
		sess->data_fd=fd;
	}
	if(sess->port_addr)
	{
		free(sess->port_addr);
		sess->port_addr=NULL;
	}
	return 1;
	
}

static void do_user(session_t *sess)//验证用户
{
	//USER zxl
	struct passwd *pw =getpwnam(sess->arg);//根据zxl参数查看是否存zxl在用户
	if(pw==NULL)
	{
		//用户不存在
		ftp_reply(sess,FTP_LOGINERR,"Longin incorrect");
		return;
	}
	sess->uid=pw->pw_uid;
	ftp_reply(sess,FTP_GIVEPWORD,"Please sepecify the password");
	
}

static void do_pass(session_t *sess)//验证秘密
{
	//PASS 123456
	struct passwd *pw=getpwuid(sess->uid);//获取pw结构体
	if(pw==NULL)
	{
		//用户不存在
		ftp_reply(sess,FTP_LOGINERR,"Longin incorrect");
		return;
	}
	printf("name=[%s]\n", pw->pw_name);
	struct spwd *sp=getspnam(pw->pw_name);//根据用户名获取已知文件信息
	if(sp==NULL)
	{
		ftp_reply(sess,FTP_LOGINERR,"Longin incorrect");
		return;
	}
	//将明文秘密加密并和已知文件中已加密的秘密比对
	char *encrypted_pass = crypt(sess->arg, sp->sp_pwdp);//crypt加密秘密参数，使用已经加密密码pwdp作种子
	//验证密码
	if(strcmp(encrypted_pass,sp->sp_pwdp)!=0)
	{
		ftp_reply(sess,FTP_LOGINERR,"Longin incorrect");
		return;
	}
	
	setgid(pw->pw_gid);
	seteuid(pw->pw_uid);
	chdir(pw->pw_dir);//改变当前目录
	
	ftp_reply(sess,FTP_LOGINOK,"Login sucesssful");
}

static void do_cwd(session_t *sess)
{

}
static void do_cdup(session_t *sess)
{

}
static void do_quit(session_t *sess)
{

}
static void do_port(session_t *sess)//记录客户端地址和端口
{	
	unsigned int v[6];
	sscanf(sess->arg,"%u,%u,%u,%u,%u,%u",&v[2],&v[3],&v[4],&v[5],&v[0],&v[1]);
	sess->port_addr=(struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	sess->port_addr->sin_family=AF_INET;
	unsigned char *p =(unsigned char *)&sess->port_addr->sin_port;
	p[0]=v[0];
	p[1]=v[1];
	
	p=(unsigned char *)&sess->port_addr->sin_addr;
	p[0]=v[2];
	p[1]=v[3];
	p[2]=v[4];
	p[3]=v[5];
	
	ftp_reply(sess, FTP_PORTOK, "PORT command successful. Consider using PASV.");
}

int get_localip(const char * eth_name, char *local_ip_addr)
{
	int ret = -1;
    register int fd;
    struct ifreq ifr;
 
	if (local_ip_addr == NULL || eth_name == NULL)
	{
		return ret;
	}
	if ((fd=socket(AF_INET, SOCK_DGRAM, 0)) > 0)
	{
		strcpy(ifr.ifr_name, eth_name);
		if (!(ioctl(fd, SIOCGIFADDR, &ifr)))
		{
			ret = 0;
			strcpy(local_ip_addr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
		}
	}
	if (fd > 0)
	{
		close(fd);
	}
    return ret;
}
static void do_pasv(session_t *sess)//应答PASV，地址发送给客户端
{
		//Entering Passive Mode (192,168,244,100,101,46).
	printf("111111111\n");
	char ip[16] = {0};
	//ip=tunable_listen_address;
	
	//getlocalip(ip);
	int ret=get_localip("ens33", ip);
	printf("222222\n");
	if(ret!=0)
	{
		printf("get_local_ip err");
		//return;
	}
	printf("ip=%s\n\r",ip);
	
	sess->pasv_listen_fd = tcp_server(ip, 0);
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	if (getsockname(sess->pasv_listen_fd, (struct sockaddr *)&addr, &addrlen) < 0)
	{
		ERR_EXIT("getsockname");
	}
	
	
	unsigned short port = ntohs(addr.sin_port);
	printf("port=%u \n",port);
	printf("port 1=%u\n\r",port>>8);
	printf("port 2=%u\n\r",port&0xFF);
	unsigned int v[4];
	sscanf(ip, "%u.%u.%u.%u", &v[0], &v[1], &v[2], &v[3]);
	char text[1024] = {0};
	sprintf(text, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).", v[0], v[1], v[2], v[3], port>>8,port&0xFF);
	printf("ip=%s\n\r",tunable_listen_address);
	printf("text=%s\n\r",text);
	
	//Entering Passive Mode (192,168,142,128,21,51).
	ftp_reply(sess, FTP_PASVOK, text);
}

static void do_type(session_t *sess)//编码格式选择响应
{
	if (strcmp(sess->arg, "A") == 0)
	{
		sess->is_ascii = 1;
		ftp_reply(sess, FTP_TYPEOK, "Switching to ASCII mode.");
	}
	else if (strcmp(sess->arg, "I") == 0)
	{
		sess->is_ascii = 0;
		ftp_reply(sess, FTP_TYPEOK, "Switching to Binary mode.");
	}
	else
	{
		ftp_reply(sess, FTP_BADCMD, "Unrecognised TYPE command.");
	}
}
static void do_stru(session_t *sess)
{

}
static void do_mode(session_t *sess)
{

}
static void do_retr(session_t *sess)
{

}
static void do_stor(session_t *sess)
{

}
static void do_appe(session_t *sess)
{

}
static void do_list(session_t *sess)//数据传输
{
	printf("xxxxxx");
	//创建数据连接
	if(get_transfer_fd(sess)==0)
	{
		printf("aaaaaa");
		return;
	}
	//150
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");
	//传输列表
	list_common(sess);
	//关闭数据套接字
	close(sess->data_fd);
	//226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
}
static void do_nlst(session_t *sess)
{

}
static void do_rest(session_t *sess)
{

}
static void do_abor(session_t *sess)
{

}
static void do_pwd(session_t *sess)//获取路径
{
	char text[2048] = {0};
	char dir[1024+1] = {0};
	getcwd(dir, 1024);//获得路径
	sprintf(text, "\"%s\"", dir);

	ftp_reply(sess, FTP_PWDOK, text);
}
static void do_mkd(session_t *sess)
{

}
static void do_rmd(session_t *sess)
{

}
static void do_dele(session_t *sess)
{

}
static void do_rnfr(session_t *sess)
{

}
static void do_rnto(session_t *sess)
{

}
static void do_site(session_t *sess)
{

}
static void do_syst(session_t *sess)
{
	ftp_reply(sess, FTP_SYSTOK, "UNIX Type: L8");
}
static void do_feat(session_t *sess)//系统特性回应
{
	ftp_lreply(sess, FTP_FEAT, "Features:");
	writen(sess->ctrl_fd, " EPRT\r\n", strlen(" EPRT\r\n"));
	writen(sess->ctrl_fd, " EPSV\r\n", strlen(" EPSV"));
	writen(sess->ctrl_fd, " MDTM\r\n", strlen(" MDTM\r\n"));
	writen(sess->ctrl_fd, " PASV\r\n", strlen(" PASV\r\n"));
	writen(sess->ctrl_fd, " REST STREAM\r\n", strlen(" REST STREAM\r\n"));
	writen(sess->ctrl_fd, " SIZE\r\n", strlen(" SIZE\r\n"));
	writen(sess->ctrl_fd, " TVFS\r\n", strlen(" TVFS\r\n"));
	writen(sess->ctrl_fd, " UTF8\r\n", strlen(" UTF8\r\n"));
	ftp_reply(sess, FTP_FEAT, "End");
}
static void do_size(session_t *sess)
{

}
static void do_stat(session_t *sess)
{

}
static void do_noop(session_t *sess)
{

}
static void do_help(session_t *sess)
{

}


