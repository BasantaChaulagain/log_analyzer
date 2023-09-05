#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <stdlib.h>
#include <Python.h>
#include "init_scan.h"
#include "utils.h"
#include "tables.h"
#include "graph.h"

using namespace std;

void write_handler(int sysno, long eid, int tid, int fd, double ts, double* forward_ts, int* ret_pid, long* ret_inode, int* flag)
{
		debugtrack("In write handler\n");
		int unitid = -1;
		int pid = get_pid(tid);
		process_table_t* pt = get_process_table(pid);

		if(is_tainted_unit(pt, tid, unitid) == false) return;

		fd_el_t *fd_el;
		fd_el = get_fd(pt, fd, eid);

		if(fd_el == NULL || fd_el->num_path == 0) {
				debug("pid %d, eid %ld, fd %d does not exist\n", pid, eid, fd);
				return;
		}

		debugtrack("Taint file: WRITE fd %d (sysno %d, eid %ld, tid %d, unitid %d) (# path %d): inode %ld, path:%s, pathtype: %s\n",
						fd, sysno, eid, tid, unitid, fd_el->num_path, fd_el->inode[fd_el->num_path-1], 
						get_absolute_path(fd_el, fd_el->num_path-1).c_str(), fd_el->pathtype[fd_el->num_path-1].c_str());
		if(fd_el->is_socket) { // it is socket
			debugtaint("%s\n", fd_el->path[fd_el->num_path-1].c_str());
			// if(strncmp(fd_el->path[fd_el->num_path-1].c_str(), "file:/var/run/nscd/socket", 25) != 0){
				int t_socket = taint_socket(fd_el->path[fd_el->num_path-1]);
				edge_proc_to_socket(tid, unitid, t_socket);
				*ret_pid = tid;
				*flag = 1;
				if (ts > *forward_ts)	*forward_ts = ts;
			// }
		} else {
			if(is_library_file(get_absolute_path(fd_el, fd_el->num_path-1)) == 0){
				taint_inode(fd_el->inode[fd_el->num_path-1], eid, get_absolute_path(fd_el, fd_el->num_path-1));
				edge_proc_to_file(tid, unitid, fd_el->inode[fd_el->num_path-1], eid);
				
				timestamp_table_t *tt;
				update_timestamp_table(tt, fd_el->inode[fd_el->num_path-1], ts, 0);
				*ret_pid = tid;
				*ret_inode = fd_el->inode[fd_el->num_path-1];
				*flag = 1;
				if (ts > *forward_ts)	*forward_ts = ts;
			}
		}
		debugtrack("w-forward_ts: %lf\t", *forward_ts);
}

void read_handler(int sysno, long eid, int tid, int fd, string exe, int ret, double ts, double* forward_ts, int* ret_pid, long* ret_inode, int* flag)
{
		debugtrack("In read handler\n");
		if (sysno == 43)	fd = ret; 	//SYS_accept
		int unitid = -1;
		int pid = get_pid(tid);
		process_table_t* pt = get_process_table(pid);
		
		if(pt == NULL) {
				printf("WARNING: PT is NULL\n");
				return;
		}

		if(fd < 3) return;

		fd_el_t *fd_el;
		fd_el = get_fd(pt, fd, eid);
		
		if(fd_el == NULL || fd_el->num_path == 0) {
				debugbt("tid %d, pid %d(%s), eid %ld, fd %d does not exist\n", tid, pid, exe.c_str(), eid, fd);
				return;
	 	}
	
		if(fd_el->is_socket == false && is_tainted_inode(fd_el->inode[fd_el->num_path-1], eid)) { // only check the last path..
				edge_file_to_proc(tid, unitid, fd_el->inode[fd_el->num_path-1], eid);
				if(taint_unit(pt, tid, unitid, exe)) {
						debugtrack("taint unit (tid %d, unitid %d, exe %s): read (sysno %d, eid %ld) (# path %d): inode %ld, path:%s, pathtype: %s\n", 
										tid, unitid, exe.c_str(),
										sysno, eid, fd_el->num_path, fd_el->inode[fd_el->num_path-1], 
										get_absolute_path(fd_el, fd_el->num_path-1).c_str(), 
										fd_el->pathtype[fd_el->num_path-1].c_str());
				}
				*ret_pid = tid;
				*ret_inode = fd_el->inode[fd_el->num_path-1];
				*flag = 1;
				timestamp_table_t *tt;
				update_timestamp_table(tt, tid, ts, 0);

				if (ts > *forward_ts)	*forward_ts = ts;
				debugtrack("r-forward_ts: %lf\t", *forward_ts);
		}
}

void fork_handler(int sysno, long eid, int tid, int a1, int ret, string exe, double ts, double* forward_ts, int* ret_pid, long* ret_inode, int* flag)
{
		debugtrack("In fork handler\n");
		int unitid = -1;
		if(a1 > 0) return;
		
		process_table_t *pt = get_process_table(get_pid(tid));

		// printf("is_tainted_unit: %d = %d\n", tid, is_tainted_unit(pt, tid, unitid));
		if(is_tainted_unit(pt, tid, unitid)) {
				taint_all_units_in_pid(ret, "");
				edge_proc_to_proc(tid, unitid, ret);
				debugbt("Taint Process: fork (sysno %d) pid %d, unitid %d, exit %d\n", sysno, tid, unitid, ret);
				
				*ret_pid = ret;
				*flag = 1;
				timestamp_table_t *tt;
				update_timestamp_table(tt, ret, ts, 0);
				
				if (ts > *forward_ts)	*forward_ts = ts;
				debugtrack("f-forward_ts: %lf\t", *forward_ts);
		}
}

void exec_handler(int sysno, long eid, int tid, string exe, long inode, double ts, double* forward_ts, int* ret_pid, long* ret_inode, int* flag)
{
		debugtrack("In exec handler\n");
		int unitid = -1;
		int pid = get_pid(tid);
		process_table_t* pt = get_process_table(pid);

		if(is_tainted_inode(inode, eid)) {
				taint_all_units_in_pid(pid, exe);
				edge_file_to_proc(tid, -1, inode, eid);
				debugtrack("taint unit (tid %d(pid %d), unitid %d, exe %s): exec (sysno %d, eid %ld), inode %ld\n", 
										tid, pid, -1, exe.c_str(),
										sysno, eid, inode);

				*ret_pid = tid;
				*ret_inode = inode;
				*flag = 1;
				timestamp_table_t *tt;
				update_timestamp_table(tt, pid, ts, 0);

				if (ts > *forward_ts)	*forward_ts = ts;
				debugtrack("e-forward_ts: %lf\t", *forward_ts);
		}
}

void ft_syscall_handler(char * buf, double ts, double* forward_ts, int* ret_pid, long* ret_inode, int* flag)
{
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
				exec_handler(sysno, eid, tid, exe, inode, ts, forward_ts, ret_pid, ret_inode, flag);
				debugtrack("new forward_ts: %lf\t", *forward_ts);
		}
		if(is_read(sysno)) {
				read_handler(sysno, eid, tid, fd, exe, ret, ts, forward_ts, ret_pid, ret_inode, flag);
				debugtrack("new forward_ts: %lf\t", *forward_ts);
		}
		if(is_write(sysno)) {
				write_handler(sysno, eid, tid, fd, ts, forward_ts, ret_pid, ret_inode, flag);
				debugtrack("new forward_ts: %lf\t", *forward_ts);
		}
		if(is_fork_or_clone(sysno)) {
				char* temp = strstr(args, "a[1]=");
				if(temp){
					temp = strtok(temp, " ");
					a1 = strtol(temp+5, NULL, 16);
				}
				fork_handler(sysno, eid, tid, a1, ret, exe, ts, forward_ts, ret_pid, ret_inode, flag);
				debugtrack("new forward_ts: %lf\t", *forward_ts);
		}
}

void table_scan_f(int user_pid, long user_inode)
{
	#ifdef GET_STATS
		int count_call_to_server = 0;
		chrono::duration<double> runtime[1000] = {};
		int lines_in_buf[1000];
		int total_logs[1000];
	#endif
	
		int max_log_len = 500;
		char* buf = (char*) malloc((200000*max_log_len) * sizeof(char));
		// char buf[16000][500];
		// int eid_list[10000], eid_index=0;
		long keywords[1000] = {0};
		string next_keyword;
		int i, k, start_index = 0, stop_index, first_iteration = 1;
		int buf_add_index, keyword_add_index, keyword_search_index;
		buf_add_index = keyword_add_index = keyword_search_index = 0;
	
		if (user_pid>0) keywords[0] = long(user_pid);
		else if (user_inode>0) keywords[0] = user_inode;
				
		PyObject *pName, *pModule, *pFunc, *pArg, *pValue;
		Py_Initialize();
		PyRun_SimpleString("import os, sys, inspect\n"
							"parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe()))))\n"
							"sys.path.insert(0, parent_dir)\n");
		pName = PyUnicode_DecodeFSDefault("client.client");
		pModule = PyImport_Import(pName);
		Py_DECREF(pName);
		if (pModule == NULL){
			PyErr_Print();
			return;
		}
		pFunc = PyObject_GetAttrString(pModule, "sse_search");
		if (pFunc==NULL || !PyCallable_Check(pFunc)){
			printf("Error initializing function.\n");
			Py_DECREF(pModule);
			return;
		}
		
		forward_ts = 0;
		char* search_type = "f";
		do {
			#ifdef GET_STATS
				auto loop_start_ts = chrono::system_clock::now();
				int total_log_lines = 0;
				long double meta_data[4];
				int meta_idx=0;
				// auto c1_send_ts_ = chrono::system_clock::now().time_since_epoch().count();
				// long double c1_send_ts = (long double)(c1_send_ts_)/1000000000;
			#endif
				
				char line[4096];
				string line_;
				next_keyword = to_string(keywords[keyword_search_index++]);
				printf("Searching for keyword: %s\n", next_keyword.c_str());

				long nxt_kw = keywords[keyword_search_index-1];
				double fw_ts_;
				timestamp_table_t *tt_;
				HASH_FIND(hh, timestamp_table, &nxt_kw, sizeof(long), tt_);
				if(tt_ != NULL)
					fw_ts_ = tt_->ts;
				else
					fw_ts_ = forward_ts;

				pArg = PyTuple_New(3);
				pValue = PyUnicode_FromString(next_keyword.c_str());
				PyTuple_SetItem(pArg, 0, pValue);
				string forward_ts_str = to_string(fw_ts_);
				pValue = PyUnicode_FromString(forward_ts_str.c_str());
				PyTuple_SetItem(pArg, 1, pValue);
				pValue = PyUnicode_FromString(search_type);
				PyTuple_SetItem(pArg, 2, pValue);
				pValue = PyObject_CallObject(pFunc, pArg);
				Py_DECREF(pArg);
				if (pValue == NULL) {
					PyErr_Print();
					fprintf(stderr,"Call failed\n");
					Py_XDECREF(pFunc);
        			Py_DECREF(pModule);
					return;
				}
				stringstream ss;
                ss << PyUnicode_AsUTF8(pValue);
				Py_DECREF(pValue);
					
			#ifdef GET_STATS
				// auto c1_recv_ts_ = chrono::system_clock::now().time_since_epoch().count();
				// long double c1_recv_ts = (long double)(c1_recv_ts_)/1000000000;
			#endif

				while(getline(ss, line_, '\n')){
					strcpy(line, line_.c_str());
					#ifdef GET_STATS
						total_log_lines++;
					#endif
					if (strtol(line, NULL, 10) == 0){
						#ifdef GET_STATS
						if (strncmp(line, "metainfo:", 9) == 0){
							char *ptr = strtok(line, ":");
							ptr = strtok(NULL, ":");
							meta_data[meta_idx++] = stold(ptr);
						}
						#endif
						continue;
					}
					char temp[4096], *ptr;
					strcpy(temp, line);
					ptr = strtok(temp, ";");
					ptr = strtok(NULL, ";");
					ptr = strtok(NULL, ";");
					if (strncmp(ptr, " UBSI_ENTRY", 11)==0 || strncmp(ptr, " UBSI_EXIT", 10)==0 || strncmp(ptr, " UBSI_DEP", 9)==0)
						continue;
					ptr = strtok(ptr, "(");
					ptr = strtok(NULL, ")");
					int sysno = atoi(ptr);
					// printf("sysno:%d, buf_add_index:%d\n", sysno, buf_add_index);
					if (is_file_create(sysno)==0 && is_exec(sysno)==0 && is_write(sysno)==0 && is_read(sysno)==0 && is_fork_or_clone(sysno)==0)
						continue;

					if(strlen(line) > 500){
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
					strcpy(buf + (buf_add_index++ * max_log_len), line);
				}
				ss.str(string());
				
				stop_index = buf_add_index-1;
			#ifdef GET_STATS
				// printf("\nIPC send time: %Lf", meta_data[0]-c1_send_ts);
				// printf("\nIPC receive time: %Lf", c1_recv_ts-meta_data[1]);

				lines_in_buf[count_call_to_server] = buf_add_index - start_index;
				total_logs[count_call_to_server] = total_log_lines;
			#endif
				
				debugtrack("Running for buf with index %d to %d\n", start_index, buf_add_index-1);

				for (k=start_index; k<=stop_index; k++){
						int flag=0, ret_pid=0, new_eid=1, l;	// ret_inode and ret_pid is the pid/inode of tainted event.
						long ret_inode=0;						// flag to denote if the event has been tainted.
						char temp[500];
						strcpy(temp, buf+k*max_log_len);
						long eid = strtol(temp, NULL, 10);
						double ts = stod(temp+11);

						if (first_iteration){
							long kw = keywords[keyword_search_index-1];
							timestamp_table_t* tt;
							HASH_FIND(hh, timestamp_table, &kw, sizeof(long), tt);
							if (tt != NULL){
								forward_ts = tt->ts;
							}
							else{
								debugtrack("tt is null. %lf: %d\n", ts, kw);
								forward_ts = ts;
							}
							first_iteration = 0;
						}

						debugtrack("\neid: %d, ts: %lf, forward_ts: %lf\t\t", eid, ts, forward_ts);
						// for(l=0; l<eid_index; l++){
						// 	if(eid_list[l]==eid){
						// 		new_eid = 0;
						// 		break;
						// 	}
						// }
						
						if(ts !=0 && ts >= forward_ts && new_eid == 1){
							// printf("\nK: %d, %s\n", k, temp);
							ft_syscall_handler(temp, ts, &forward_ts, &ret_pid, &ret_inode, &flag);
							// eid_list[eid_index++] = (int)eid;

							// extract pid and inode from the logs.
							if (flag == 1){
								debugtrack("\nret_pid: %d, ret_inode: %ld\n", ret_pid, ret_inode);
								int pid_exist = 0, inode_exist = 0;
								for (i=0; i<=keyword_add_index; i++){
									if (ret_pid == keywords[i]){
										pid_exist = 1;
										break;
									}
								}
								for (i=0; i<=keyword_add_index; i++){
									if (ret_inode == keywords[i]){
										inode_exist = 1;
										break;
									}
								}
								debugtrack("pid_exist %d, inode_exist %d\n", pid_exist, inode_exist);
								if (pid_exist == 0 && ret_pid > 0)
									keywords[++keyword_add_index] = long(ret_pid);
								if (inode_exist == 0 && ret_inode > 0)
									keywords[++keyword_add_index] = ret_inode;
							}
							// add a line to the new index only if the prev log is tainted, else replace it.
							if (flag == 0)
								buf_add_index--;
						}
				}
				start_index = buf_add_index;
				first_iteration = 1;

				debugtrack("\nnext keyword: %ld\n", keywords[keyword_search_index]);
				debugtrack("lines in buf: %d\n", buf_add_index);

			#ifdef GET_STATS
				auto loop_end_ts = chrono::system_clock::now();
				runtime[count_call_to_server++] = loop_end_ts-loop_start_ts;
			#endif
		} while (keywords[keyword_search_index] != 0);

		Py_XDECREF(pFunc);
		Py_DECREF(pModule);
		if (Py_FinalizeEx() < 0)
			return;
	
		#ifdef GET_STATS
			printf("\nTotal calls to server: %d\n", count_call_to_server);
			printf("\nkeyword\t#total_logs\t#relevant_logs\truntime\n");
			for (k=0; k<count_call_to_server; k++)
				printf("%ld\t%d\t%d\t%lf\n", keywords[k], total_logs[k], lines_in_buf[k], runtime[k].count());
		#endif
	// }
}


int main(int argc, char** argv)
{
		auto start = chrono::system_clock::now();
		bool load_init_table = true;

		FILE *fp;

		int opt = 0;
		char *log_name = NULL;
		char *init_table_name = NULL;
		char *f_name = NULL;
		char *p_name = NULL;

		forward_ts = 0;

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
								printf("Usage: ./UBSI_ft [-i log_file] [-t init_table] [-f file_inode] [-p process_pid]\n");
								return 0;
								break;
				}
		}
		
		if((log_name == NULL && init_table_name == NULL) || (user_inode == 0 && user_pid == 0)) {
				printf("Usage: ./UBSI_ft [-i log_file] [-t init_table] [-f file_inode] [-p process_pid]\n");
				return 0;
		}

		if (log_name != NULL){
			if((fp = fopen(log_name, "r")) == NULL) {
					printf("Error: Cannot open the log file: %s\n", log_name);
					printf("Usage: ./UBSI_bt [-i log_file] [-t init_table] [-f file_inode] [-p process_pid]\n");
					return 0;
			}
			fclose(fp);
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
		
		if(log_name != NULL){
				fp = fopen(log_name, "r");
				generate_fp_table(fp);
				print_fp_table();
		}
		
		if(user_pid > 0) {
				printf("user taint tid = %d, pid = %d\n", user_pid, get_pid(user_pid));
				taint_all_units_in_pid(user_pid, "start_node");
		}

		if(user_inode > 0) {
				string path;
				long user_eid = check_inode_list(user_inode, &path, &forward_ts);
				if(user_eid < 0) 
					taint_inode(user_inode, user_eid, path);
				debugtaint("taint inode from initial : %ld [%ld]\n", user_inode, user_eid);
				if (path[0] == ' ') path = path.substr(1);
				taint_inode(user_inode, user_eid, path);
		}
		if(log_name != NULL){
				fclose(fp);
		}
		else{
				printf("calling table scan.\n");
				table_scan_f(user_pid, user_inode);
		}

		fp = fopen("AUDIT_ft.gv", "w");

		emit_graph(fp);
		emit_graph_detail(fp);
		fclose(fp);

		auto end = chrono::system_clock::now();
		chrono::duration<double> elapsed_seconds = end-start;
		printf("elapsed time: %lf\n", elapsed_seconds.count());

		return 1;
}

