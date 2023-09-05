#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <stack>
#include <sstream>
#include <chrono>
#include <ctime>
#include <stdlib.h>
#include "init_scan.h"
#include "utils.h"
#include "tables.h"
#include "graph.h"

using namespace std;

void write_handler_(int sysno, long eid, int tid, int fd, string exe, double ts, double* backtrack_ts, int* ret_pid, long* ret_inode, int* flag)
{
	debugtrack("In write handler\n");
		int unitid = -1;
		int pid = get_pid(tid);
		process_table_t* pt = get_process_table(pid);

		fd_el_t *fd_el;
		fd_el = get_fd(pt, fd, eid);

		if(fd_el == NULL || fd_el->num_path == 0) {
				debug("pid %d, eid %ld, fd %d does not exist\n", pid, eid, fd);
				return;
		}
		debugtrack("sock:%d, np:%d, inode:%ld, path:%s, tainted_inode:%d\n", fd_el->is_socket, fd_el->num_path, fd_el->inode[fd_el->num_path-1], fd_el->path[fd_el->num_path-1].c_str(), is_tainted_inode(fd_el->inode[fd_el->num_path-1], eid));

		if(fd_el->is_socket == false && is_tainted_inode(fd_el->inode[fd_el->num_path-1], eid)) { // only check the last path..
				edge_proc_to_file(tid, unitid, fd_el->inode[fd_el->num_path-1], eid);
				if(taint_unit(get_process_table(pid), tid, unitid, exe)) {
						debugtrack("Taint Unit (tid %d, unitid %d, exe %s): WRITE (sysno %d, eid %ld) (# path %d): inode %ld, path:%s, pathtype: %s\n", 
										tid, unitid, exe.c_str(),
										sysno, eid, fd_el->num_path, fd_el->inode[fd_el->num_path-1], 
										get_absolute_path(fd_el, fd_el->num_path-1).c_str(), 
										fd_el->pathtype[fd_el->num_path-1].c_str());
				}
				*ret_pid = tid;
				*ret_inode = fd_el->inode[fd_el->num_path-1];
				*flag = 1;
				timestamp_table_t *tt;
				update_timestamp_table(tt, tid, ts, 1);

				if (ts < *backtrack_ts)	*backtrack_ts = ts;
				debugtrack("w-backtrack_ts: %lf\t", *backtrack_ts);
		}
		// printf("EXIT from write handler\n");
}

void read_handler_(int sysno, long eid, int tid, int fd, int ret, double ts, double* backtrack_ts, int* ret_pid, long* ret_inode, int* flag){
		debugtrack("In read handler\n");
		if (sysno == 43)	fd = ret; 	//SYS_accept
		int unitid = -1;
		int pid = get_pid(tid);
		process_table_t* pt = get_process_table(pid);

		if(pt == NULL)	{
			debugtrack("pt is null\n");
			return;}

		debugtrack("is_tainted_unit: %d, return if 0.\n", is_tainted_unit(pt, tid, unitid));
		if(is_tainted_unit(pt, tid, unitid) == false)	return;
	
		if(fd < 3) return;

		fd_el_t *fd_el;
		fd_el = get_fd(pt, fd, eid);
		if(fd_el == NULL || fd_el->num_path == 0) {
				debugtrack("pid %d, eid %ld, fd %d does not exist\n", pid, eid, fd);
				return;
		}

		debugtrack("Taint file: READ fd %d (sysno %d, eid %ld, tid %d, unitid %d) (# path %d): inode %ld, path:%s, pathtype: %s, is_socket: %d\n",
						fd, sysno, eid, tid, unitid, fd_el->num_path, fd_el->inode[fd_el->num_path-1], 
						get_absolute_path(fd_el, fd_el->num_path-1).c_str(), fd_el->pathtype[fd_el->num_path-1].c_str(), fd_el->is_socket);
		if(fd_el->is_socket) { // it is socket
			debugtrack("is socket: %s\n", fd_el->path[fd_el->num_path-1].c_str());
			// if(strncmp(fd_el->path[fd_el->num_path-1].c_str(), "file:/var/run/nscd/socket", 25) != 0){
				int t_socket = taint_socket(fd_el->path[fd_el->num_path-1]);
				edge_socket_to_proc(tid, unitid, t_socket);

				*flag = 1;
				*ret_pid = tid;
				if (ts < *backtrack_ts)	*backtrack_ts = ts;
			// }
		} else {
				debugtrack("taint inode from read : %ld [%ld] - %ld\n", fd_el->inode[fd_el->num_path-1], fd_el->eid, eid);
				if(is_library_file(get_absolute_path(fd_el, fd_el->num_path-1)) == 0){
					taint_inode(fd_el->inode[fd_el->num_path-1], eid, get_absolute_path(fd_el, fd_el->num_path-1));
					edge_file_to_proc(tid, unitid, fd_el->inode[fd_el->num_path-1], eid);

					timestamp_table_t *tt;
					update_timestamp_table(tt, fd_el->inode[fd_el->num_path-1], ts, 1);
					
					*flag = 1;
					*ret_pid = tid;
					*ret_inode = fd_el->inode[fd_el->num_path-1];
					if (ts < *backtrack_ts)	*backtrack_ts = ts;
				}
		}
		debugtrack("r-backtrack_ts: %lf\t", *backtrack_ts);
		// printf("EXIT from read handler\n");
}

void fork_handler_(int sysno, long eid, int tid, int a1, int ret, string exe, double ts, double* backtrack_ts, int* ret_pid, long* ret_inode, int* flag){
		debugtrack("In fork handler\n");
		int unitid = -1;
		if(a1 > 0) return;
		if(is_tainted_pid(ret)) {
				edge_proc_to_proc(tid, unitid, ret);
				if(taint_unit(get_process_table(get_pid(tid)), tid, unitid, exe))
				{
						debugtrack("Taint Process: fork (sysno %d) pid %d, unitid %d, exit %d, exe %s\n", sysno, tid, unitid, ret, exe.c_str());
				}
				*flag = 1;
				*ret_pid = tid;
				timestamp_table_t *tt;
				update_timestamp_table(tt, tid, ts, 1);

				if (ts < *backtrack_ts)	*backtrack_ts = ts;
				debugtrack("f-backtrack_ts: %lf\t", *backtrack_ts);
		}
		debugtrack("EXIT from fork handler\n");
}

void exec_handler_(int sysno, long eid, int tid, string cwd, string path, long inode, double ts, double* backtrack_ts, int* ret_pid, long* ret_inode, int* flag){
		debugtrack("In exec handler, eid: %ld, sysno: %d\n", eid, sysno);
		int unitid = -1;
		int pid = get_pid(tid);
		process_table_t* pt = get_process_table(pid);

		if(is_tainted_pid(pid)) {
				edge_file_to_proc(tid, unitid, inode, eid);
				debugtrack("taint inode from exec : %ld [%ld]\n", inode, eid);
				if(is_library_file(get_absolute_path(cwd,path)) == 0){
					if(taint_inode(inode, eid, get_absolute_path(cwd,path))) { // only check the last path..
							debugtaint("Taint File (tid %d, unitid %d): Execve (sysno %d, eid %ld), inode %ld, path:%s\n",
											tid, unitid,
											sysno, eid, inode, get_absolute_path(cwd,path).c_str());
					}
					*flag = 1;
					*ret_pid = tid;
					*ret_inode = inode;
					timestamp_table_t *tt;
					update_timestamp_table(tt, inode, ts, 1);
					if (ts < *backtrack_ts)	*backtrack_ts = ts;
				}
				debugtrack("e-backtrack_ts: %lf\t", *backtrack_ts);
		}
		debugtrack("EXIT from exec handler\n");
}

void bt_syscall_handler_(char * buf, double ts, double* backtrack_ts, int* ret_pid, long* ret_inode, int* flag){
		// printf("In bt syscall handler: %s", buf);
		char *ptr, args[100], list[12][256];
		int i=0, j=0, sysno, fd, ret, tid;
		string exe, cwd, path;
		long eid, inode, a1;

		ptr = strtok(buf, ";");
		while (ptr != NULL){
			if(i==3)
				strncpy(list[j++], ptr, 255);
			if(i==0 || i==2 || i==4 || i==7 || i==10 || i==14 || i==17 || i==18 || i==28 || i==30 || i==31){
				strcpy(list[j++], ptr);
			}
			ptr = strtok(NULL, ";");
			i++;
		}

		eid = strtol(list[0], NULL, 10);
		sysno = get_sysno(list[1]);
		ret = atoi(list[2]);
		strcpy(args, list[3]);
		tid = atoi(list[4]);
		exe = list[5];
		fd = atoi(list[6]);
		cwd = list[9];
		if(sysno == 59){
			path = list[10];
			inode = strtol(list[11], NULL, 10);
		}
		else{
			path = list[7];
			inode = strtol(list[8], NULL, 10);
		}

		if(is_exec(sysno)) {
				exec_handler_(sysno, eid, tid, cwd, path, inode, ts, backtrack_ts, ret_pid, ret_inode, flag);
				debugtrack("new backtrack_ts: %lf\t", *backtrack_ts);
		}
		if(is_read(sysno)) {
				read_handler_(sysno, eid, tid, fd, ret, ts, backtrack_ts, ret_pid, ret_inode, flag);
				debugtrack("new backtrack_ts: %lf\t", *backtrack_ts);
		}
		if(is_write(sysno) && !is_socket(sysno)) {
				write_handler_(sysno, eid, tid, fd, exe, ts, backtrack_ts, ret_pid, ret_inode, flag);
				debugtrack("new backtrack_ts: %lf\t", *backtrack_ts);
		}
		if(is_fork_or_clone(sysno)) {
				char* temp = strstr(args, "a[1]=");
				if(temp){
					temp = strtok(temp, " ");
					a1 = strtol(temp+5, NULL, 16);
				}
				fork_handler_(sysno, eid, tid, a1, ret, exe, ts, backtrack_ts, ret_pid, ret_inode, flag);
				debugtrack("new backtrack_ts: %lf\t", *backtrack_ts);
		}
		// printf("fields:\teid:%ld, sysno:%d, tid:%d, exe:%s, fd:%d, ret:%d, a1:%ld\n", eid, sysno, tid, exe.c_str(), fd, ret, a1);
}


void table_scan(int user_pid, long user_inode, FILE *fp){
	char buf[4096];
	int max_log_len = 500;
	int first_iteration = 1;

	long kw;
	if (user_pid>0) kw = long(user_pid);
	else if (user_inode>0) kw = user_inode;

	stack<std::string> lines;
	while (fgets(buf, sizeof(buf), fp) != NULL) {
        lines.push(buf);
    }
	backtrack_ts = 4000000000;
	char line[4096];

	while (!lines.empty()) {
		strcpy(line, lines.top().c_str());
		if (strtol(line, NULL, 10) == 0){
			lines.pop();
			continue;
		}
		char temp[4096], *ptr;
		strcpy(temp, line);
		ptr = strtok(temp, ";");
		ptr = strtok(NULL, ";");
		ptr = strtok(NULL, ";");
		if (strncmp(ptr, " UBSI_ENTRY", 11)==0 || strncmp(ptr, " UBSI_EXIT", 10)==0 || strncmp(ptr, " UBSI_DEP", 9)==0){
			lines.pop();
			continue;
		}
		ptr = strtok(ptr, "(");
		ptr = strtok(NULL, ")");
		int sysno = atoi(ptr);
		if (is_file_create(sysno)==0 && is_exec(sysno)==0 && is_write(sysno)==0 && is_read(sysno)==0 && is_fork_or_clone(sysno)==0){
			lines.pop();
			continue;
		}
		
		if(strlen(line) > max_log_len){
			char t[4096], *ptr;
			strcpy(t, line);
			line[0] = '\0';
			
			ptr = strtok(t, ";");
			while (ptr != NULL){
				if(strlen(ptr)>220){
					ptr[220]='\0';
				}
				strcat(line, ptr);
				strcat(line, ";");
				
				ptr = strtok(NULL, ";");
			}
			line[strlen(line)]='\0';
		}

		int flag=0, ret_pid=0, new_eid=1, l;	// flag is to denote if the event has been tainted.
		long ret_inode=0;						// ret_inode and ret_pid is the pid/inode of tainted event.
		long eid = strtol(temp, NULL, 10);
		double ts = stod(temp+11);

		if (first_iteration){
			timestamp_table_t* tt;
			HASH_FIND(hh, timestamp_table, &kw, sizeof(long), tt);
			if (tt != NULL){
				debugtrack("tt is not null. %lf: %d\n", tt->ts, kw);
				backtrack_ts = tt->ts;
			}
			else{
				debugtrack("tt is null. %lf: %d\n", ts, kw);
				backtrack_ts = ts;
			}
			first_iteration = 0;
		}
		bt_syscall_handler_(line, ts, &backtrack_ts, &ret_pid, &ret_inode, &flag);

        lines.pop();
    }
}


int main(int argc, char** argv)
{
		auto start_ts = chrono::system_clock::now();
		bool load_init_table = true;

		FILE *fp;

		int opt = 0;
		char *log_name = NULL;
		char *init_table_name = NULL;
		char *f_name = NULL;
		char *p_name = NULL;

		backtrack_ts = 0;

		while ((opt = getopt(argc, argv, "i:f:p:t:h")) != -1) {
				switch(opt) {
						case 'i':
								log_name = optarg;
								printf("Log file name=%s\n", log_name);
								break;
						case 't':
								init_table_name = optarg;
								printf("Init table name=%s\n", init_table_name);
								break;
						case 'f':
								f_name = optarg;
								user_inode = atol(f_name);
								printf("User Tainted File Inode=%s(%ld)\n", f_name, user_inode);
								break;
						case 'p':
								p_name = optarg;
								user_pid = atoi(p_name);
								printf("User Tainted Process Id=%s(%d)\n", p_name, user_pid);
								break;
						case 'h':
								printf("Usage: ./UBSI_bt [-i log_file] [-t init_table] [-f file_inode] [-p process_pid]\n");
								return 0;
								break;
				}
		}
		
		if((log_name == NULL && init_table_name == NULL) || (user_inode == 0 && user_pid == 0)) {
				printf("Usage: ./UBSI_bt [-i log_file] [-t init_table] [-f file_inode] [-p process_pid]\n");
				return 0;
		}

		if (log_name != NULL){
			if((fp = fopen(log_name, "r")) == NULL) {
					printf("Error: Cannot open the log file: %s\n", log_name);
					printf("Usage: ./UBSI_bt [-i log_file] [-t init_table] [-f file_inode] [-p process_pid]\n");
					return 0;
			}
		}
		
		if(log_name != NULL && init_table_name == NULL) {
				init_table_name = (char*) malloc(sizeof(char)*1024);
				sprintf(init_table_name, "%s_init_table.dat", log_name);
				printf("Init table name=%s\n", init_table_name);
		}

		init_table();

		printf("Load init_table (%s)\n", init_table_name);
		if(load_init_tables(init_table_name) == 0) load_init_table = false;
		
		if(!load_init_table && log_name != NULL) {
				if(!init_scan(log_name)) return 0;
				printf("Save init_table (%s)\n", init_table_name);
				save_init_tables(init_table_name);
		}
		
		if(user_pid > 0) {
				printf("user taint tid = %d, pid = %d\n", user_pid, get_pid(user_pid));
				taint_all_units_in_pid(user_pid, "start_node");
		}

		if(user_inode > 0) {
				string path;
				long user_eid = check_inode_list(user_inode, &path, &backtrack_ts);
				if(user_eid < 0)
					taint_inode(user_inode, user_eid, path);
				debugtaint("taint inode from initial : %ld [%ld]\n", user_inode, user_eid);
				if (path[0] == ' ') path = path.substr(1);
				taint_inode(user_inode, user_eid, path);
		}
		// if(log_name != NULL){
		// 		fclose(fp);
		// }
		// else{
		// 		printf("calling table scan.\n");
		// 		table_scan(user_pid, user_inode);
		// }

		table_scan(user_pid, user_inode, fp);
		fclose(fp);
		
		fp = fopen("AUDIT_bt.gv", "w");

		emit_graph(fp);
		emit_graph_detail(fp);
		fclose(fp);

		auto end_ts = chrono::system_clock::now();
		chrono::duration<double> elapsed_seconds = end_ts-start_ts;
		printf("elapsed time: %lf\n", elapsed_seconds.count());

		return 1;
}