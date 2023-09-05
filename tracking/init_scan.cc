#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/syscall.h>
#include <set>
#include "uthash.h"
#include "utlist.h"
#include "utils.h"
#include "tables.h"

#define UENTRY 0xffffff9c
#define UEXIT 0xffffff9b
#define MREAD1 0xffffff38
#define MREAD2 0xffffff37
#define MWRITE1 0xfffffed4
#define MWRITE2 0xfffffed3

bool is_init_scan;
long num_syscall = 0;
double backtrack_ts = 0;
double forward_ts = 0;

void process_exit(int tid)
{

}

void process_group_exit(int tid)
{
		process_exit(tid);
}

void set_pid(int tid, int pid)
{
		struct thread_process_t *ut;
		int ppid;
		// printf("%d-%d-%d\n", tid, pid);

		HASH_FIND_INT(thread2process_table, &pid, ut);  /* looking for parent thread's pid */
		if(ut == NULL) {
				ppid = pid;
		} else {
			ppid = ut->pid;
		}
		ut = NULL;

		HASH_FIND_INT(thread2process_table, &tid, ut);  /* id already in the hash? */
		if (ut == NULL) {
				// printf("tid doesn't exist for: %d\n", tid);
				ut = (thread_process_t*) malloc(sizeof(thread_process_t));
				ut->tid = tid;
				ut->pid = ppid;
				HASH_ADD_INT(thread2process_table, tid, ut);
				// printf("addition to table: tid-%d, pid-%d\n", tid, ppid);
		} else {
				// printf("tid exists for: %d\n", tid);
				ut->pid = ppid;
		}
}

void fd_pipe_handler_(long tid, int sysno, long pid, long eid, int fd0_num, int fd1_num){
		//SYS_pipe, SYS_pipe2
		process_table_t *pt;
		fd_table_t *ft;
		fd_el_t *fd_el0, *fd_el1;

		pid	= get_pid(tid);
		pt = get_process_table(pid);

		if (fd0_num){
			fd_el0 = new fd_el_t;
			fd_el0->eid = eid;
			fd_el0->num_path = 0;
			fd_el0->is_pair = false;
			fd_el0->is_pipe = true;
			fd_el0->piped_fd = fd0_num;
		}

		if (fd1_num){
			fd_el1 = new fd_el_t;
			fd_el1->eid = eid;
			fd_el1->num_path = 0;
			fd_el1->is_pair = false;
			fd_el1->is_pipe = true;
			fd_el1->piped_fd = fd1_num;
		}

		HASH_FIND_INT(pt->fd_table, &fd0_num, ft);

		if(ft == NULL) {
				ft = (fd_table_t *)malloc(sizeof(fd_table_t));
				ft->fd = fd0_num;
				ft->fd_el = NULL;
				// printf("added fd0: %d to pid: %d\n", fd0_num, pid);
				HASH_ADD_INT(pt->fd_table, fd, ft);
		}
		DL_APPEND(ft->fd_el, fd_el0);

		HASH_FIND_INT(pt->fd_table, &fd1_num, ft);

		if(ft == NULL) {
				ft = (fd_table_t *)malloc(sizeof(fd_table_t));
				ft->fd = fd1_num;
				ft->fd_el = NULL;
				// printf("added fd1: %d to pid: %d\n", fd1_num, pid);
				HASH_ADD_INT(pt->fd_table, fd, ft);
		}
		DL_APPEND(ft->fd_el, fd_el1);
}

void fd_pipe_handler(char *buf, int tid, int sysno)
{
		//SYS_pipe, SYS_pipe2
		process_table_t *pt;
		fd_table_t *ft;
		char *ptr;
		fd_el_t *fd_el0, *fd_el1;
		int pid, fd0, fd1;
		long eid;

	 	pid	= get_pid(tid);
		pt = get_process_table(pid);

		ptr = strstr(buf, ":");
		eid = strtol(ptr+1, NULL, 10);

		ptr = strstr(ptr, "type=FD_PAIR");
		assert(ptr);
		
		ptr = strstr(ptr, " fd0=");
		fd0 = strtol(ptr+5, NULL, 10);
		ptr = strstr(ptr, " fd1=");
		fd1 = strtol(ptr+5, NULL, 10);

		fd_el0 = new fd_el_t;
		fd_el0->eid = eid;
		fd_el0->num_path = 0;
		fd_el0->is_pair = false;
		fd_el0->is_pipe = true;
		fd_el0->piped_fd = fd1;

		fd_el1 = new fd_el_t;
		fd_el1->eid = eid;
		fd_el1->num_path = 0;
		fd_el1->is_pair = false;
		fd_el1->is_pipe = true;
		fd_el1->piped_fd = fd0;

		HASH_FIND_INT(pt->fd_table, &fd0, ft);

		if(ft == NULL) {
				ft = (fd_table_t *)malloc(sizeof(fd_table_t));
				ft->fd = fd0;
				ft->fd_el = NULL;
				// printf("added fd0: %d to pid: %d\n", fd0, pid);
				HASH_ADD_INT(pt->fd_table, fd, ft);
		}
		DL_APPEND(ft->fd_el, fd_el0);

		HASH_FIND_INT(pt->fd_table, &fd1, ft);

		if(ft == NULL) {
				ft = (fd_table_t *)malloc(sizeof(fd_table_t));
				ft->fd = fd1;
				ft->fd_el = NULL;
				// printf("added fd1: %d to pid: %d\n", fd1, pid);
				HASH_ADD_INT(pt->fd_table, fd, ft);
		}
		DL_APPEND(ft->fd_el, fd_el1);
}

void fd_pair_handler_(long tid, int sysno, long pid, long eid, long ret, long a0, int fd0_num, int fd1_num){
		//SYS_socketpair, SYS_dup, SYS_dup2, SYS_dup3
		process_table_t *pt;
		fd_table_t *ft;
		fd_el_t *fd_el;
		int fd, old_fd;

		pid	= get_pid(tid);
		pt = get_process_table(pid);

		fd_el = new fd_el_t;
		fd_el->eid = eid;
		fd_el->num_path = 0;
		fd_el->is_pair = true;
		fd_el->is_pipe = false;

		if(sysno == SYS_dup || sysno == SYS_dup2 || sysno == SYS_dup3)
		{
				fd = ret;
				old_fd = a0;
				fd_el->paired_fd = old_fd;
		} else if (sysno == SYS_socketpair) {
			fd = fd0_num;
			fd_el->paired_fd = fd1_num;
				//assert(0);
		} 
		
		HASH_FIND_INT(pt->fd_table, &fd, ft);

		if(ft == NULL) {
				ft = (fd_table_t *)malloc(sizeof(fd_table_t));
				ft->fd = fd;
				ft->fd_el = NULL;
				// printf("%d - %d: added fd_p: %d to pid: %d\n", sysno, eid, fd, pid);
				HASH_ADD_INT(pt->fd_table, fd, ft);
		}
		DL_APPEND(ft->fd_el, fd_el);
}

void fd_pair_handler(char *buf, int tid, int sysno)
{
		//SYS_socketpair, SYS_dup, SYS_dup2, SYS_dup3
		process_table_t *pt;
		fd_table_t *ft;
		char *ptr;
		fd_el_t *fd_el;
		int pid, fd, old_fd;
		long eid;

	 	pid	= get_pid(tid);
		pt = get_process_table(pid);

		ptr = strstr(buf, ":");
		eid = strtol(ptr+1, NULL, 10);

		fd_el = new fd_el_t;
		fd_el->eid = eid;
		fd_el->num_path = 0;
		fd_el->is_pair = true;
		fd_el->is_pipe = false;

	
		if(sysno == SYS_dup || sysno == SYS_dup2 || sysno == SYS_dup3)
		{
				ptr = strstr(ptr, " exit=");
				fd = strtol(ptr+6, NULL, 10);

				ptr = strstr(ptr, " a0=");
				old_fd = strtol(ptr+4, NULL, 16);
				fd_el->paired_fd = old_fd;
		} else if (sysno == SYS_socketpair) {
				//assert(0);
		} 
		
		HASH_FIND_INT(pt->fd_table, &fd, ft);

		if(ft == NULL) {
				ft = (fd_table_t *)malloc(sizeof(fd_table_t));
				ft->fd = fd;
				ft->fd_el = NULL;
				// printf("%d - %d: added fd_p: %d to pid: %d\n", sysno, eid, fd, pid);
				HASH_ADD_INT(pt->fd_table, fd, ft);
		}
		DL_APPEND(ft->fd_el, fd_el);
}

void socket_fd_handler_(long eid, char* fd0_ip, char* fd0_port, fd_table_t *ft){
		int num;
		fd_el_t *fd_el;

		fd_el = new fd_el_t;
		fd_el->eid = eid;
		fd_el->is_socket = true;
		fd_el->num_path = 1;
		fd_el->is_pair = false;
		fd_el->is_pipe = false;

		if(fd0_ip != " ") {
				char *ptr = strstr(fd0_ip, "path");
				if (ptr != NULL)
					strncpy(ptr, "file", 4);
				else if(fd0_port != " "){
					strcat(fd0_ip,":");
					strcat(fd0_ip, fd0_port+1);
				}
				fd_el->path[0] = fd0_ip+1;
				debug("saddr: %s\n", fd_el->path[0].c_str());
				DL_APPEND(ft->fd_el, fd_el);
		}
		// fd_el->~fd_el_t();
}

void socket_fd_handler(char *buf, long eid, fd_table_t *ft)
{
		char *ptr;
		int num;
		fd_el_t *fd_el;

		fd_el = new fd_el_t;
		fd_el->eid = eid;
		fd_el->is_socket = true;
		fd_el->num_path = 1;
		fd_el->is_pair = false;
		fd_el->is_pipe = false;

		ptr = strstr(buf, "type=SOCKADDR");
		if(ptr != NULL) {
				fd_el->path[0] = extract_sockaddr(ptr, "saddr=", 6);
				debug("saddr: %s\n", fd_el->path[0].c_str());
				DL_APPEND(ft->fd_el, fd_el);
		} else {
				fd_el->~fd_el_t();
		}
}

void file_fd_handler_(long eid, char* cwd, char* fd0_name, char* fd1_name, char* fd0_type, char* fd1_type, long fd0_inode, long fd1_inode, fd_table_t *ft){
		int num;
		fd_el_t *fd_el;

		//fd_el = (fd_el_t*) malloc (sizeof(fd_el_t));
		fd_el = new fd_el_t;
		fd_el->eid = eid;
		fd_el->is_socket = false;
		fd_el->is_pair = false;
		fd_el->is_pipe = false;

		if(cwd != " ") {
				fd_el->cwd = cwd+1;
		} else {
				fprintf(stderr, "File open log does not have \"CWD\". Try again after sort the log file with \"sortlog\" command.\n");
				return;
		}

		if (fd0_name != " " && fd0_type != " " && fd0_inode){
				num = 0;
				fd_el->path[num] = fd0_name+1;
				fd_el->pathtype[num] = fd0_type;
				fd_el->inode[num] = fd0_inode;
		}
		if (fd1_name != " " && fd1_type != " " && fd1_inode){
				num = 1;
				fd_el->path[num] = fd1_name+1;
				fd_el->pathtype[num] = fd1_type;
				fd_el->inode[num] = fd1_inode;
		}
		fd_el->num_path = num+1;
		DL_APPEND(ft->fd_el, fd_el);
}

void file_fd_handler(char *buf, long eid, fd_table_t *ft)
{
		char *ptr;
		int num;
		fd_el_t *fd_el;

		//fd_el = (fd_el_t*) malloc (sizeof(fd_el_t));
		fd_el = new fd_el_t;
		fd_el->eid = eid;
		fd_el->is_socket = false;
		fd_el->is_pair = false;
		fd_el->is_pipe = false;

		ptr = strstr(buf, "type=CWD");
		if(ptr != NULL) {
				fd_el->cwd = extract_string(ptr, "cwd=", 4);
		} else {
				fprintf(stderr, "File open log does not have \"CWD\". Try again after sort the log file with \"sortlog\" command.\n");
				return;
		}

		while(1)
		{
				ptr = strstr(ptr, "type=PATH");
				if(ptr == NULL) break;
				ptr+=9;
				if(extract_int(ptr, "item=", 5, &num) == 0) break;
				if(num > MAX_PATH) assert(0);
				fd_el->path[num] = extract_string(ptr, "name=", 5);
				fd_el->pathtype[num] = extract_string(ptr, " nametype=", 10);
				extract_long(ptr, "inode=", 6, &(fd_el->inode[num]));
				debug("item %d, inode %ld, name %s\n", num, fd_el->inode[num], fd_el->path[num].c_str());
		}
		fd_el->num_path = num+1;
		DL_APPEND(ft->fd_el, fd_el);
}

void update_inode_table_(int sysno, long eid, time_t time, unsigned int mil, long inode, char* type, char* name){
		char *ptr;
		inode_table_t *it;
		debugtrack("%ld: update inode table for inode:%ld, name:%s\n", eid, inode, name);

		HASH_FIND_LONG(inode_table, &inode, it);
		if(it == NULL)
		{
			debugtrack("inode not found in table. %ld, %ld\n", inode, eid);
				it = new inode_table_t;
				it->inode = inode;
				inode_el_t el;
				el.name = name;
				if (is_file_create(sysno) || sysno == SYS_open || sysno == SYS_openat){
					el.created_eid = eid;
					el.created_time = time;
					el.created_time_mil = mil;
					el.deleted_eid = el.deleted_time = el.deleted_time_mil = 0;
				}
				else if (is_file_delete(sysno)){
					el.deleted_eid = eid;
					el.deleted_time = time;
					el.deleted_time_mil = mil;
					el.created_eid = el.created_time = el.created_time_mil = 0;
				}
				it->list.push_back(el);
				HASH_ADD(hh, inode_table, inode, sizeof(long), it);
				debugtrack("inode added to table. %ld, %ld, %ld\n", inode, eid, time);
		}

		// scan the entire list to see if the name already exists.
		int path_exists = 0;
		for(vector<inode_el_t>::iterator iit = it->list.begin(); iit != it->list.end(); iit++)
		{
			if(iit->name == name)	path_exists=1;

			if(iit->name == name && is_file_delete(sysno)){
				iit->deleted_eid = eid;
				iit->deleted_time = time;
				iit->deleted_time_mil = mil;
				break;
			}
		}
		if(path_exists == 0){
			debugtrack("Adding another inode_el_t to inode:%ld, name:%s, eid:%ld\n", it->inode, name, eid);
			inode_el_t el;
			el.name = name;
			if (is_file_create(sysno)|| sysno == SYS_open || sysno == SYS_openat || sysno == SYS_rename){
				el.created_eid = eid;
				el.created_time = time;
				el.created_time_mil = mil;
				el.deleted_eid = el.deleted_time = el.deleted_time_mil = 0;
			}
			else if (is_file_delete(sysno)){
				el.deleted_eid = eid;
				el.deleted_time = time;
				el.deleted_time_mil = mil;
				el.created_eid = el.created_time = el.created_time_mil = 0;
			}
			it->list.push_back(el);
		}
}

void fd_handler_(long tid, int sysno, long pid, long eid, long a0, long ret, char* cwd, char* fd0_name, char* fd1_name, char* fd0_type, char* fd1_type, long fd0_inode, long fd1_inode, char* fd0_ip, char* fd0_port){
		//SYS_open, SYS_openat, SYS_creat, SYS_accept, SYS_connect
		char *ptr;
		int fd;
		process_table_t *pt;
		fd_table_t *ft;

		pid = get_pid(tid);

		if(sysno == 42) { // connect: a0 is a fd.
				fd = a0;
		} else {
				fd = ret;
		}
		
		pt = get_process_table(pid);
		
		HASH_FIND_INT(pt->fd_table, &fd, ft);
		if(ft == NULL) {
				ft = (fd_table_t *)malloc(sizeof(fd_table_t));
				ft->fd = fd;
				ft->fd_el = NULL;
				// printf("added fd: %d to pid: %d\n", fd, pid);
				HASH_ADD_INT(pt->fd_table, fd, ft);
		}
		if(sysno == SYS_open || sysno == SYS_openat || sysno == SYS_creat) {
			debugtrack("File FD handler event %ld, pid %d, sysno %d, fd0:%s, inode:%ld, cwd:%s\n", eid, pid, sysno, fd0_name, fd0_inode, cwd);
				file_fd_handler_(eid, cwd, fd0_name, fd1_name, fd0_type, fd1_type, fd0_inode, fd1_inode, ft);
		} 
		else {
			debugtrack("Socket FD handler event %ld, pid %d, sysno %d, fd0 %s\n", eid, pid, sysno, fd0_ip);
				socket_fd_handler_(eid, fd0_ip, fd0_port, ft);
		}
		
		debug("FD handler event %ld, pid %d, sysno %d\n", eid, pid, sysno); 

}

void fd_handler(char *buf, int tid, int sysno)
{
		//SYS_open, SYS_openat, SYS_creat, SYS_accept, SYS_connect
		char *ptr;
		int pid, fd;
		long eid;
		process_table_t *pt;
		fd_table_t *ft;

	 	pid	= get_pid(tid);
		ptr = strstr(buf, ":");
		eid = strtol(ptr+1, NULL, 10);

		if(sysno == 42) { // connect: a0 is a fd.
				ptr = strstr(ptr, " a0=");
				fd = strtol(ptr+4, NULL, 16);
		} else {
				ptr = strstr(ptr, " exit=");
				fd = strtol(ptr+6, NULL, 10);
		}
		
		pt = get_process_table(pid);
		
		HASH_FIND_INT(pt->fd_table, &fd, ft);
		if(ft == NULL) {
				ft = (fd_table_t *)malloc(sizeof(fd_table_t));
				ft->fd = fd;
				ft->fd_el = NULL;
				// printf("added fd: %d to pid: %d\n", fd, pid);
				HASH_ADD_INT(pt->fd_table, fd, ft);
		}
		if(sysno == SYS_open || sysno == SYS_openat || sysno == SYS_creat) {
				file_fd_handler(buf, eid, ft);
		} else {
				socket_fd_handler(buf, eid, ft);
		}
		
//		debug("FD handler event %ld, pid %d, sysno %d\n", eid, pid, sysno); 
}

int get_sysno(char *syscall){
	if (strcmp(syscall, " UBSI_ENTRY")==0 || strcmp(syscall, " UBSI_EXIT")==0 || strcmp(syscall, " UBSI_DEP")==0) return -1;
	char *ptr = strtok(syscall, "(");
	ptr = strtok(NULL, ")");

	return atoi(ptr);
}

int get_tid(char *tid){
	char *ptr = strtok(tid, "_");
	return atoi(ptr);
}

void init_event_handler(char *buf)
{
	// printf("%s", buf);
	int i = 0, sysno;
	char list[35][256], *ptr;
	long a0, a1, a2, pid, ppid, ret, tid, eid;
	ptr = strtok(buf, ";");

	while (ptr != NULL){
		char tmp[4096];
		strcpy(tmp, ptr);
		if(strncmp(tmp, " a[0]", 5) == 0)
			strncpy(list[i++], tmp, 255);
		else
			strcpy(list[i++], ptr);
		ptr = strtok(NULL, ";");
	}
	num_syscall++;

	// for (i=0; i<35; i++){
	// 	printf("%d: %s\t", i, list[i]);
	// }
	// printf("\n");
	
	// Fields from the event
	eid = strtol(list[0], NULL, 10);
	sysno = get_sysno(list[2]);
	tid = get_tid(list[5]);
	pid = strtol(list[7], NULL, 10);
	ppid = strtol(list[8], NULL, 10);
	ret = strtol(list[3], NULL, 10);

	ptr = strstr(list[4], "a[2]=");
	if (ptr){
		ptr = strtok(ptr, " ");
		a2 = strtol(ptr+5, NULL, 16);
	}

	ptr = strstr(list[4], "a[1]=");
	if (ptr){
		ptr = strtok(ptr, " ");
		a1 = strtol(ptr+5, NULL, 16);
	}

	ptr = strstr(list[4], "a[0]=");
	if (ptr){
		ptr = strtok(ptr, " ");
		a0 = strtol(ptr+5, NULL, 16);
	}

	if(sysno == SYS_clone || sysno == SYS_fork || sysno == SYS_vfork) // clone or fork
	{
		if(sysno == SYS_clone && a2 > 0) { // thread_creat event
			set_pid(ret, pid);
		}
	} 
	else if( sysno == SYS_execve || sysno == 322 || sysno == SYS_exit || sysno == SYS_exit_group) { // execve, exit or exit_group
		if(sysno == SYS_exit_group) { // exit_group call
				// TODO: need to finish all thread in the process group
				process_group_exit(tid);
		}
		process_exit(tid);
	} 
	else if(sysno == SYS_open || sysno == SYS_openat || sysno == SYS_accept || sysno == SYS_connect || sysno == SYS_accept4 || is_file_create(sysno) || is_file_delete(sysno) || is_file_rename(sysno)) {
			char *cwd = list[28];
			char *fd0_name = list[17];
			char *fd1_name = list[24];
			char *fd0_ip = list[19];
			char *fd0_port = list[20];
			char *fd0_type = list[15];
			char *fd1_type = list[22];
			long fd0_inode = strtol(list[18], NULL, 10);
			long fd1_inode = strtol(list[25], NULL, 10);
			int flag = atoi(list[34]);
			time_t time;
			unsigned int mil;

			extract_time_(list[1], &time, &mil);

			fd_handler_(tid, sysno, pid, eid, a0, ret, cwd, fd0_name, fd1_name, fd0_type, fd1_type, fd0_inode, fd1_inode, fd0_ip, fd0_port);
			// if (sysno != SYS_accept || sysno != SYS_connect || sysno != SYS_accept4 ){
			if (is_file_create(sysno) || is_file_delete(sysno)){
					update_inode_table_(sysno, eid, time, mil, fd0_inode, fd0_type, fd0_name);
			}
			if (is_file_rename(sysno)){
					update_inode_table_(sysno, eid, time, mil, fd1_inode, fd1_type, fd1_name);
			}
			if ((sysno == SYS_open || sysno == SYS_openat) && flag==1){
				// printf("eid: %ld, flag: %d\n", eid, flag);
					update_inode_table_(sysno, eid, time, mil, fd0_inode, fd0_type, fd0_name);
			}
	} 
	else if(sysno == SYS_socketpair || sysno == SYS_dup || sysno == SYS_dup2 || sysno == SYS_dup3) {
			int fd0_num = atoi(list[14]);
			int fd1_num = atoi(list[21]);
			fd_pair_handler_(tid, sysno, pid, eid, ret, a0, fd0_num, fd1_num);
	} 
	else if (sysno == SYS_pipe || sysno == SYS_pipe2) {
			long fd0_num = strtol(list[14], NULL, 10);
			long fd1_num = strtol(list[21], NULL, 10);
			fd_pipe_handler_(tid, sysno, pid, eid, fd0_num, fd1_num);
	} 
}

void init_syscall_handler(char *buf)
{
		char *ptr;
		int sysno;
		long a0, a1, a2, pid, ret, tid;
		char comm[64];
		bool succ;

		//debug("BUF: %s", buf);
		ptr = strstr(buf, " syscall=");
		if(ptr == NULL) {
				printf("ptr = NULL: %s\n", buf);
				return;
		}

		num_syscall++;

		sysno = strtol(ptr+9, NULL, 10);
		ptr = strstr(ptr, " pid=");
		tid = strtol(ptr+5, NULL, 10);

		succ = get_succ(buf);

		if(succ == true && (sysno == SYS_clone || sysno == SYS_fork || sysno == SYS_vfork)) // clone or fork
		{
				ptr = strstr(buf, " a2=");
				a2 = strtol(ptr+4, NULL, 16);

				if(sysno == SYS_clone && a2 > 0) { // thread_creat event
						ptr = strstr(buf, " exit=");
						ret = strtol(ptr+6, NULL, 10);
						set_pid(ret, tid);
				}
		} else if(succ == true && ( sysno == SYS_execve || sysno == 322 
								|| sysno == SYS_exit || sysno == SYS_exit_group)) { // execve, exit or exit_group
				if(sysno == SYS_exit_group) { // exit_group call
						// TODO: need to finish all thread in the process group
						process_group_exit(tid);
				}
				process_exit(tid);
	} else if(succ == true && (sysno == SYS_open || sysno == SYS_openat || sysno == SYS_creat || sysno == SYS_accept || sysno == SYS_connect || sysno == SYS_accept4)) {
				fd_handler(buf, tid, sysno);
	} else if(succ == true && (sysno == SYS_socketpair || sysno == SYS_dup || sysno == SYS_dup2 || sysno == SYS_dup3)) {
			fd_pair_handler(buf, tid, sysno);
	} else if (succ == true && (sysno == SYS_pipe || sysno == SYS_pipe2)) {
			fd_pipe_handler(buf, tid, sysno);
	} else if(sysno == SYS_connect) { // connect may fail with errno 115 (operatiion in progress), but it should be handled.
				fd_handler(buf, tid, sysno);
	}
}

void insert_unit_table(process_table_t *pt, unit_list_t *list, int clusterid)
{
		struct unit_list_t *tmp;
		struct unit_table_t *unit;
		DL_FOREACH(list, tmp) {
				debug("insert_unit_table: (%d-%d) - ", tmp->id.tid, tmp->id.unitid);
				HASH_FIND(hh, pt->unit_table, &(tmp->id), sizeof(unit_el_t), unit);
				if(unit == NULL) {
						debug("CANNOT find, create new instance.\n");
//						assert(0);
						unit_table_t *new_unit = (unit_table_t*) malloc (sizeof(unit_table_t));
						new_unit->id.tid = tmp->id.tid;
						new_unit->id.unitid = tmp->id.unitid;
						new_unit->clusterid = clusterid;
						HASH_ADD(hh, pt->unit_table, id, sizeof(unit_el_t), new_unit);
				} else {
						debug("find. update clusterid\n");
						unit->clusterid = clusterid;
				}
		}
}

void merge_unit_cluster(int pid, int root, int newid)
{
		debug("pid %d, merge clusters %d and %d\n", pid, root, newid);
		struct process_table_t *pt;
		struct unit_cluster_t *ut_root, *ut_new;
		struct unit_list_t *tmp;
		struct unit_table_t *unit;

		HASH_FIND_INT(process_table, &pid, pt);
		if(pt == NULL) assert(0);

		HASH_FIND_INT(pt->unit_cluster, &root, ut_root);
		HASH_FIND_INT(pt->unit_cluster, &newid, ut_new);

		if(ut_root == NULL) assert(0);
		if(ut_new == NULL) return;

		DL_FOREACH(ut_new->list, tmp) {
				HASH_FIND(hh, pt->unit_table, &(tmp->id), sizeof(unit_el_t), unit);
				if(unit == NULL) assert(0);
				unit->clusterid = root;
		}

		DL_CONCAT(ut_root->list, ut_new->list);
		HASH_DEL(pt->unit_cluster, ut_new);

		insert_unit_table(pt, ut_root->list, root);
		//print_unit_cluster(pt->pid, ut_root);
}

void merge_unit_cluster(int pid, int root, unit_list_t *ut_new)
{
		debug("pid %d, merge clusters %d and new list\n", pid, root);
		struct process_table_t *pt;
		struct unit_cluster_t *ut_root;
		struct unit_list_t *tmp;
		struct unit_table_t *unit;

		HASH_FIND_INT(process_table, &pid, pt);
		if(pt == NULL) assert(0);

		HASH_FIND_INT(pt->unit_cluster, &root, ut_root);
		if(ut_root == NULL) assert(0);

		DL_CONCAT(ut_root->list, ut_new);

		insert_unit_table(pt, ut_root->list, root);
		//print_unit_cluster(pt->pid, ut_root);
}

void insert_new_unit_cluster(process_table_t *pt, unit_list_t *list)
{
		debug("pid %d, insert new unit cluster %d\n", pt->pid, pt->next_cluster_id);
		unit_cluster_t *new_ut = (unit_cluster_t*) malloc(sizeof(unit_cluster_t));
		new_ut->clusterid = pt->next_cluster_id++;
		new_ut->list = NULL;

		DL_CONCAT(new_ut->list, list);
		HASH_ADD_INT(pt->unit_cluster, clusterid, new_ut);
		insert_unit_table(pt, list, new_ut->clusterid);
		//print_unit_cluster(pt->pid, new_ut);
}

void insert_single_unit(process_table_t *pt, int tid, int unitid)
{
		unit_list_t *list;
		list = (unit_list_t*) malloc(sizeof(unit_list_t));
		
		list->id.tid = tid;
		list->id.unitid = unitid;
		list->prev = list->next = NULL;

		insert_new_unit_cluster(pt, list);
}

void unit_clustering(unit_el_t *tu, int n)
{
		int pid = get_pid(tu[0].tid);
		
		struct process_table_t *pt = NULL;
		struct unit_table_t *ut = NULL;
		unit_list_t *new_list = NULL;
		set<int> clusters;

		pt = get_process_table(pid);

		for(int i = 0; i < n; i++)
		{
				debug("pid %d, looking for a hash, %d-%d: ", pid, tu[i].tid, tu[i].unitid);
				HASH_FIND(hh, pt->unit_table, &(tu[i]), sizeof(unit_el_t), ut);
				if(ut != NULL) {
						debug("found in the cluster %d\n", ut->clusterid);
						clusters.insert(ut->clusterid);
				} else {
						debug("NOT found, create new instance\n");
						struct unit_table_t *newt = (unit_table_t*) malloc(sizeof(unit_table_t));
						newt->id.tid = tu[i].tid;
						newt->id.unitid = tu[i].unitid;
						HASH_ADD(hh, pt->unit_table, id, sizeof(unit_el_t), newt);
						
						unit_list_t *el = (unit_list_t*) malloc(sizeof(unit_list_t));
						el->id.tid = tu[i].tid;
						el->id.unitid = tu[i].unitid;
						el->prev = el->next = NULL;
						DL_APPEND(new_list, el);
				}
		}
		
		if(!clusters.empty()) {
				int root_cluster;
				for (std::set<int>::iterator it=clusters.begin(); it!=clusters.end(); ++it) 
				{
						if(it == clusters.begin()) root_cluster = *it;
						else {
								merge_unit_cluster(pid, root_cluster, *it);
						}
				}
				merge_unit_cluster(pid, root_cluster, new_list);
		} else {
				// insert new unit cluster.
				insert_new_unit_cluster(pt, new_list);
		}
		print_all_unit_clusters(pid);
}

void unit_handler(char *buf)
{
		int i = 0;
		char *ptr;
		int tid, unitid;
		
		unit_el_t tu[2048];

		ptr = strstr(buf, " tid=");
		tid = strtol(ptr+5, NULL, 10);
		ptr = strstr(ptr, " unitid=");
		unitid = strtol(ptr+8, NULL, 10);
		
		tu[i].tid = tid;
		tu[i++].unitid = unitid;
		//printf("*tid %d, unitid %d\n", tid, unitid);

		ptr = strstr(buf, "\"");
		ptr++;

		while(1) {
				if(sscanf(ptr, "%d-%d,", &tid, &unitid) < 2) break;
				//printf("tid %d, unitid %d\n", tid, unitid);
				tu[i].tid = tid;
				tu[i++].unitid = unitid;
				ptr = strstr(ptr, ",");
				if(ptr == NULL) break;
				if(*(++ptr) == '\"') break;
		}
		unit_clustering(tu, i);
}

int buffering(char *buf, long *size)
{
		int ret = 0;
		static long last_eid = 0;
		static char stag_buf[1048576];
		long eid;
		char *ptr;
		
		if(buf == NULL) {
				if(strncmp(stag_buf, "type=SYSCALL",12) == 0) {
						init_syscall_handler(stag_buf);
						*size = strlen(stag_buf);
						stag_buf[0] = '\0';
						ret = 1;
				} 
				return ret;
		}

		if(strncmp(buf, "type=UNIT",9) == 0) {
				if(strncmp(stag_buf, "type=SYSCALL",12) == 0) {
						init_syscall_handler(stag_buf);
						*size = strlen(stag_buf);
						ret = 1;
						stag_buf[0] = '\0';
				}
				unit_handler(buf);
				return ret;
		}

		ptr = strstr(buf, ":");
		if(ptr == NULL) return 0;
		eid = strtol(ptr+1, NULL, 10);

		if(last_eid == eid) {
				strcat(stag_buf, buf);
		} else {
			// printf("stag_buf: %s\n", stag_buf);
				if(strncmp(stag_buf, "type=SYSCALL",12) == 0) {
						init_syscall_handler(stag_buf);
						*size = strlen(stag_buf);
						ret = 1;
				} 
				strcpy(stag_buf, buf);
				last_eid = eid;
		}
		return ret;
}

void load_unit_list(unit_cluster_t *uc, FILE *fp)
{
		unsigned int num;
		unit_el_t *l;

		fread(&num, sizeof(unsigned int), 1, fp);
		debug("load unit_list size %d\n", num);

		l = (unit_el_t*) malloc (sizeof(unit_el_t) * num);
		fread(l, sizeof(unit_el_t), num, fp);

		for(int i = 0; i < num; i++)
		{
				unit_list_t *el = new unit_list_t; //(unit_list_t*) malloc(sizeof(unit_list_t));
				el->id.tid = l[i].tid;
				el->id.unitid = l[i].unitid;
				el->prev = el->next = NULL;
				debug("%d-%d\n", el->id.tid, el->id.unitid);
				DL_APPEND(uc->list, el);
		}
		free(l);
}

void save_unit_list(unit_list_t *list, FILE *fp)
{
		int i = 0;
		unsigned int num;
		unit_el_t *l;
		unit_list_t *elt;

		DL_COUNT(list, elt, num);
		l = (unit_el_t*) malloc (sizeof(unit_el_t) * num);
		debug("save unit_list size %d\n", num);

		fwrite(&num, sizeof(unsigned int), 1, fp);

		DL_FOREACH(list, elt) {
				l[i].tid = elt->id.tid;
				l[i].unitid = elt->id.unitid;
				debug("%d-%d\n", l[i].tid, l[i].unitid);
				i++;
		}

		fwrite(l, sizeof(unit_el_t), num, fp);
		free(l);
}

int load_unit_cluster(process_table_t *pt, FILE *fp)
{
		unsigned int num;
		
		fread(&num, sizeof(unsigned int), 1, fp);
		debug("load_unit_cluster: num %d\n", num);
		if(num == 0) return 0;

		
		for(int i = 0; i < num; i++)
		{
				unit_cluster_t *ut = new unit_cluster_t;//(unit_cluster_t*) malloc(sizeof(unit_cluster_t));
				ut->list = NULL;
				fread(&(ut->clusterid), sizeof(int), 1, fp);
				debug("load unit cluster: clusterid %d\n", ut->clusterid);
				load_unit_list(ut, fp);
				HASH_ADD_INT(pt->unit_cluster, clusterid, ut);
		}
		return num;
}

int save_unit_cluster(unit_cluster_t *unit_cluster, FILE *fp)
{
		unit_cluster_t *ut, *tmp;
		unsigned int num = HASH_COUNT(unit_cluster);

		fwrite(&num, sizeof(unsigned int), 1, fp);
		debug("save_unit_cluster: # of cluster %d\n", num);
		if(unit_cluster == NULL) return 0;

		HASH_ITER(hh, unit_cluster, ut, tmp) {
				fwrite(&(ut->clusterid), sizeof(int), 1, fp);
				debug("save unit cluster: clusterid %d\n", ut->clusterid);
				save_unit_list(ut->list, fp);
		}
		return num;
}

int load_unit_table(process_table_t *pt, FILE *fp)
{
		unit_table_t *ut, *tmp;
		unsigned int num;

		fread(&num, sizeof(unsigned int), 1, fp);
		debug("load_unit_table: num %d\n", num);
		if(num == 0) return 0;
		
		for(int i = 0; i < num; i++)
		{
				unit_table_t *ut = (unit_table_t*) malloc (sizeof(unit_table_t));

				fread(&(ut->id), sizeof(unit_el_t), 1, fp);
				fread(&(ut->clusterid), sizeof(int), 1, fp);
				debug("(%d,%d)-%d\n", ut->id.tid, ut->id.unitid, ut->clusterid);
				HASH_ADD(hh, pt->unit_table, id, sizeof(unit_el_t), ut);
		}

		return num;
}

int save_unit_table(unit_table_t *unit_table, FILE *fp)
{
		unit_table_t *ut, *tmp;
		unsigned int num = HASH_COUNT(unit_table);

		fwrite(&num, sizeof(unsigned int), 1, fp);
		debug("save_unit_table: num %d\n", num);
		if(unit_table == NULL) return 0;

		HASH_ITER(hh, unit_table, ut, tmp) {
				fwrite(&(ut->id), sizeof(unit_el_t), 1, fp);
				fwrite(&(ut->clusterid), sizeof(int), 1, fp);
				debug("(%d,%d)-%d\n", ut->id.tid, ut->id.unitid, ut->clusterid);
		}
		return num;
}

string load_string(FILE *fp)
{
		unsigned int num;
		char *t;
		string str;

		fread(&num, sizeof(unsigned int), 1, fp);
		t = (char*) malloc (sizeof(char)*(num+1));
		
		if(num == 0) return string(); 

		fread(t, 1, num , fp);
		
		t[num] = '\0';
		str = string(t);
		free(t);
		//debug("load string: %s\n", str.c_str());
		return str;
		
}

void save_string(string str, FILE *fp)
{
		unsigned int num = str.size();
		fwrite(&num, sizeof(unsigned int), 1, fp);
		if(num == 0) return;

		fwrite(str.c_str(),1, num , fp);
}

void load_fd_list(fd_table_t *ft, FILE *fp)
{
		unsigned int num;
		fd_el_t *elt;

		typedef struct {
				long eid;
				bool is_socket;
				int num_path;
				bool is_pair;
				int paired_fd;
				bool is_pipe;
				int piped_fd;
				long inode[MAX_PATH];
		} temp_t;

		//temp_t t;

		fread(&num, sizeof(unsigned int), 1, fp);
		debug("load fd_list size %d\n", num);

		if(num == 0) return;
		
		for(int i = 0; i < num; i++)
		{
				//fd_el_t *el = (fd_el_t*) malloc(sizeof(fd_el_t));
				fd_el_t *el = new fd_el_t;
				fread(el, sizeof(temp_t), 1, fp);
				//memcpy(el, &t, sizeof(temp_t));
				//debug("load: eid %ld, inode[0] = %ld, num_path %d\n", el->eid, el->inode[0], el->num_path);
				el->cwd = load_string(fp);
				for(int j = 0; j < el->num_path; j++)
				{
						//el->path[j] = string();
						el->path[j] = load_string(fp);
						el->pathtype[j] = load_string(fp);
						//debug("load path: %s\n", el->path[j].c_str());
						//debug("load pathtype: %s\n", el->pathtype[j].c_str());
				}
				DL_APPEND(ft->fd_el, el);
		}
		debug("load fd_list size %d done\n", num);
}

void save_fd_list(fd_el_t *list, FILE *fp)
{
		unsigned int num;
		fd_el_t *elt;

		typedef struct {
				long eid;
				bool is_socket;
				int num_path;
				bool is_pair;
				int paired_fd;
				bool is_pipe;
				int piped_fd;
				long inode[MAX_PATH];
		} temp_t;

		temp_t t;

		DL_COUNT(list, elt, num);
		debug("save fd_list size %d, fp %ld\n", num, ftell(fp));

		fwrite(&num, sizeof(unsigned int), 1, fp);
		if(num == 0) return;

		DL_FOREACH(list, elt) {
				memcpy(&t, elt, sizeof(temp_t));
				fwrite(&t, sizeof(temp_t), 1, fp);
				debug("eid %ld, inode[0] = %ld,\n", t.eid, t.inode[0]);
				save_string(elt->cwd, fp);
				for(int i = 0; i < elt->num_path; i++)
				{
						save_string(elt->path[i], fp);
						save_string(elt->pathtype[i], fp);
				}
		}
}

int load_fd_table(process_table_t *pt, FILE *fp)
{
		fd_table_t *ft;
		unsigned int num;

		fread(&num, sizeof(unsigned int), 1, fp);
		debug("load_fd_table: # of table: %d\n", num);
		if(num == 0) return 0;

		for(int i = 0; i < num; i++)
		{
				ft = new fd_table_t;//(fd_table_t *)malloc(sizeof(fd_table_t));
				ft->fd_el = NULL;
				fread(&(ft->fd), sizeof(int), 1, fp);
				debugnow("load_fd_list: fd %d\n", ft->fd);
				load_fd_list(ft, fp);
				HASH_ADD_INT(pt->fd_table, fd, ft);
				debugnow("fd_table size: %u\n", HASH_COUNT(pt->fd_table));
		}
		debug("table loaded\n");
		return num;
}

int save_fd_table(fd_table_t* fd_table, FILE *fp)
{
		fd_table_t *ft, *tmp;
		unsigned int num = HASH_COUNT(fd_table);

		fwrite(&num, sizeof(unsigned int), 1, fp);
		debugnow("save_fd_table: # table %d\n", num);
		if(num == 0) return 0;
		//if(fd_table == NULL) return 0;

		HASH_ITER(hh, fd_table, ft, tmp) {
				fwrite(&(ft->fd), sizeof(int), 1, fp);
				debugnow("save_fd_list: fd %d\n", ft->fd);
				// printf("%d\t", ft->fd);
				save_fd_list(ft->fd_el, fp);
		}

		return num;
}

void load_process_table(FILE *fp)
{
		process_table_t *pt, *tmp;
		unsigned int num;
		int pid;
		int n_fd_table, n_unit_table, n_unit_cluster;
		n_fd_table = n_unit_table = n_unit_cluster = 0;

		fread(&num, sizeof(unsigned int), 1, fp);
		debug("load_process_table: num_proc: %d\n", num);		
		for(int i = 0; i < num; i++)
		{
				loadBar(i, num, 10, 50);
				pt = new process_table_t; //(process_table_t*) malloc (sizeof(process_table_t));
				pt->unit_cluster = NULL;
				pt->unit_table = NULL;
				pt->fd_table = NULL;

				fread(&(pt->pid), sizeof(int), 1, fp);
				fread(&(pt->next_cluster_id), sizeof(int), 1, fp);

				debug("Load_process_table: proc %d\n", pt->pid);

				n_unit_cluster += load_unit_cluster(pt, fp);
				n_unit_table += load_unit_table(pt, fp);
				n_fd_table += load_fd_table(pt, fp);
				debug("pid %d, fd_table size %u\n", pt->pid, HASH_COUNT(pt->fd_table));

				HASH_ADD_INT(process_table, pid, pt);
		}

		printf("  Unit_cluter: %d elements loaded.\n", n_unit_cluster);
		printf("  Unit_table: %d elements loaded.\n", n_unit_table);
		printf("  FD_table: %d elements loaded.\n", n_fd_table);
}

void save_process_table(FILE *fp)
{
		process_table_t *pt, *tmp;
		unsigned int num = HASH_COUNT(process_table);
		int n_fd_table, n_unit_table, n_unit_cluster;
		n_fd_table = n_unit_table = n_unit_cluster = 0;

		fwrite(&num, sizeof(unsigned int), 1, fp);
		debug("save_process_table: num_proc: %d\n", num);
		// printf("\n----------process table:\n");
		HASH_ITER(hh, process_table, pt, tmp) {
				fwrite(&(pt->pid), sizeof(int), 1, fp);
				fwrite(&(pt->next_cluster_id), sizeof(int), 1, fp);

				// printf("\tsave_process_table: proc %d\n", pt->pid);
				// printf("%d\t=====\t", pt->pid);

				n_unit_cluster += save_unit_cluster(pt->unit_cluster, fp);
				n_unit_table += save_unit_table(pt->unit_table, fp);
				n_fd_table += save_fd_table(pt->fd_table, fp);
		}
		// printf("\n----------------\n");
		printf("  Process table: %d elements saved.\n", num);
		printf("    Unit_cluter: %d elements saved.\n", n_unit_cluster);
		printf("    Unit_table: %d elements saved.\n", n_unit_table);
		printf("    FD_table: %d elements saved.\n", n_fd_table);
}

void load_thread2process_table(FILE *fp)
{
		typedef struct {
				int tid;
				int pid;
		} temp_t;

		temp_t *t;
		thread_process_t *pt;
		
		unsigned int num;
		fread((void*)&num, sizeof(unsigned int), 1, fp);	
		t = (temp_t*) malloc(sizeof(temp_t) * num);

		debug("size of thread2process table %u\n", num);
		fread((void*)t, sizeof(temp_t), num, fp);

		for(int i = 0; i < num; i++)
		{
				pt = new thread_process_t; //(thread_process_t*) malloc (sizeof(thread_process_t));
				pt->pid = t[i].pid;
				pt->tid = t[i].tid;
				debug("tid:%d-pid:%d\n", pt->tid, pt->pid);
				HASH_ADD_INT(thread2process_table, tid, pt);
		}
		free(t);
		printf("  Thread2process table: %d elements loaded.\n", num);
}

void save_thread2process_table(FILE *fp)
{
		typedef struct {
				int tid;
				int pid;
		} temp_t;

		temp_t *t;
		thread_process_t *pt, *tmp;
		
		unsigned int num = HASH_COUNT(thread2process_table);
		t = (temp_t*) malloc(sizeof(temp_t) * num);
		int i=0;

		debug("size of thread2process table %u\n", num);
		// printf("----------thread to process table:\n");
		fwrite((void*)&num, sizeof(unsigned int), 1, fp);	
		HASH_ITER(hh, thread2process_table, pt, tmp) {
				//if(pt->pid != pt->tid) debug("%d-%d\n", pt->pid, pt->tid);
				debug("tid:%d-pid:%d\t", pt->tid, pt->pid);
				// printf("%d-%d\t", pt->tid, pt->pid);
				t[i].pid = pt->pid;
				t[i].tid = pt->tid;
				i++;
		}
		// printf("\n----------------\n");
		debug("i = %d, num = %d\n", i, num);
		fwrite((void*)t, sizeof(temp_t), num, fp);
		free(t);
		printf("  Thread2process table: %d elements saved.\n", num);
}


void save_inode_list(vector<inode_el_t> list, FILE* fp){
		unsigned int num = list.size();
		debug("save inode_list size %d, fp %ld\n", num, ftell(fp));
		fwrite(&num, sizeof(unsigned int), 1, fp);
		if(num == 0) return;

		for(auto elem: list){
				fwrite(&elem.created_eid, sizeof(elem.created_eid), 1, fp);
				fwrite(&elem.deleted_eid, sizeof(elem.deleted_eid), 1, fp);
				save_string(elem.name, fp);
				fwrite(&elem.created_time, sizeof(elem.created_time), 1, fp);
				fwrite(&elem.deleted_time, sizeof(elem.deleted_time), 1, fp);
				fwrite(&elem.created_time_mil, sizeof(elem.created_time_mil), 1, fp);
				fwrite(&elem.deleted_time_mil, sizeof(elem.deleted_time_mil), 1, fp);
				debug("eid %ld, name = %s,\n", elem.created_eid, elem.name.c_str());
		}
}

void save_inode_table(FILE* fp){
		inode_table_t *it, *tmp;
		unsigned int num = HASH_COUNT(inode_table);

		fwrite(&num, sizeof(unsigned int), 1, fp);
		debug("save_inode_table: num_inode: %d\n", num);
		if(num == 0) return;
		HASH_ITER(hh, inode_table, it, tmp) {
				debug("\tsave_inode_table: inode %ld\n", it->inode);
				fwrite(&(it->inode), sizeof(long), 1, fp);
				save_inode_list(it->list, fp);
		}
		printf("  Inode table: %d elements saved.\n", num);
}

void load_inode_list(inode_table_t *it, FILE* fp){
		unsigned int num;
		inode_el_t *elt;

		fread(&num, sizeof(unsigned int), 1, fp);
		debug("load inode_list size %d\n", num);
		if(num == 0) return;

		for(int i = 0; i < num; i++)
		{
				elt = new inode_el_t;
				fread(&elt->created_eid, sizeof(elt->created_eid), 1, fp);
				fread(&elt->deleted_eid, sizeof(elt->deleted_eid), 1, fp);
				elt->name = load_string(fp);
				fread(&elt->created_time, sizeof(elt->created_time), 1, fp);
				fread(&elt->deleted_time, sizeof(elt->deleted_time), 1, fp);
				fread(&elt->created_time_mil, sizeof(elt->created_time_mil), 1, fp);
				fread(&elt->deleted_time_mil, sizeof(elt->deleted_time_mil), 1, fp);

				it->list.push_back(*elt);
		}
		debug("load inode_list size %d done\n", num);
}

void load_inode_table(FILE *fp){
		inode_table_t *it;
		unsigned int num;

		fread(&num, sizeof(unsigned int), 1, fp);
		debug("load_inode_table: num_inode: %d\n", num);	
		if(num == 0) return;

		for(int i = 0; i < num; i++)
		{
				it = new inode_table_t;
				it->list = {};
				fread(&(it->inode), sizeof(long), 1, fp);
				debug("load_inode_list: inode %ld\n", it->inode);
				load_inode_list(it, fp);
				HASH_ADD(hh, inode_table, inode, sizeof(long), it);
		}
		printf("  Inode table: %d elements loaded.\n", num);
}

int save_init_tables(const char *name)
{
		FILE *fp;

		if((fp=fopen(name, "w")) == NULL) {
				return 0;
		}
		
		fwrite(&num_syscall, sizeof(long), 1, fp);
		save_thread2process_table(fp);
		save_process_table(fp);
		save_inode_table(fp);
		fclose(fp);
		return 1;
}

int load_init_tables(const char *name) 
{
		FILE *fp;

		if((fp=fopen(name, "r")) == NULL) {
				return 0;
		}

		is_init_scan = true;
		process_table = NULL;
		thread2process_table = NULL;
		inode_table = NULL;
		fread(&num_syscall, sizeof(long), 1, fp);

		printf("num_syscall = %ld\n", num_syscall);
		load_thread2process_table(fp);
		load_process_table(fp);
		load_inode_table(fp);
		fclose(fp);
		is_init_scan = false;

		//string test = merge_path(get_fd(3872, 51, 2911494624));
		//printf("mergeed string: %s\n", test.c_str());

		//print_all_unit_clusters(21200);
		return 1;
}

int init_scan(const char *name)
{
		FILE *fp;
		char buf[1048576], buf2[1048576];
		int i = 0;
		long fend, fcur, ftmp;
		char *ptr;

		if((fp=fopen(name, "r")) ==NULL) {
				return 0;
		}
		
		is_init_scan = true;

		long stag_buf_size =0;
		int max_line = 0;

		printf("Init scanning....\n");
		fseek(fp, 0L, SEEK_END);
		fend = ftell(fp);
		fseek(fp, 0L, SEEK_SET);
		
		i = 0;
		fcur = ftell(fp);
		fgets(buf, 1048576, fp);
		while(!feof(fp)) 
		{
			if(i++ > 10000) {
						loadBar(fcur, fend, 10, 50);
						i = 0;
			 }

				// buffering(buf, &stag_buf_size);
				
				init_event_handler(buf);

				fcur = ftell(fp);
				// printf("fcur is %ld\n", fcur);
				fgets(buf, 1048576, fp);
		}

		// if(buffering(NULL, &stag_buf_size)) {
		// 		//num_events++;
		// }
		fclose(fp);
		
		//printf("total events: %u\n", num_events);
		printf("# of syscall: %ld\n", num_syscall);
		is_init_scan = false;

		return 1;
}
