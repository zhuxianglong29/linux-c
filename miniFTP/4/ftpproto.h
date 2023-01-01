#ifndef _FTPPROTO_H_
#define _FTPPROTO_H_

#include "session.h"

void handle_child(session_t *sess);
int get_localip(const char * eth_name, char *local_ip_addr);
void ftp_reply(session_t *sess,int status,const char *text);


#endif
