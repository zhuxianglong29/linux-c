#include "session.h"
#include "ftpproto.h"
#include "privparent.h"
#include "common.h"
#include "privsock.h"
#include "sysutil.h"

void begin_session(session_t *sess)
{
	activate_oobinline(sess->ctrl_fd);
	/*
	int sockfds[2];//父子进程通信
	if(socketpair(PF_UNIX,SOCK_STREAM,0,sockfds)<0)
		ERR_EXIT("socketpair");
	*/
	priv_sock_init(sess);
	
	pid_t pid;
	pid =fork();
	if(pid<0)//如果出现错误，fork返回一个负值不一定=-1
		ERR_EXIT("fork");
		
	if(pid==0)
	{
		//ftp服务进程，处理通信相关
		/*
		close(sockfds[0]);
		sess->child_fd=sockfds[1];
		*/
		priv_sock_set_child_context(sess);
		handle_child(sess);
	}
	else
	{
		
		//nobody进程，内部使用的进程
		/*
		close(sockfds[1]);
		sess->parent_fd =sockfds[0];
		*/
		priv_sock_set_parent_context(sess);
		handle_parent(sess);
	}
}
