#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <sys/syscall.h>
#include "UBSI_utils.h"
#include "UBSI_csv.h"
#include "UBSI_auditBridge.h"

int UBSIAnalysis = FALSE;
int CSVOUT = FALSE;
int UBSI_buffer(char *buf);
void UBSI_sig_handler(int signo);
int UBSI_buffer_flush();
int waitForEnd = FALSE;
int socketRead = FALSE;
int fileRead = FALSE;
int dirRead = FALSE;
char socketPath[256];
char filePath[256];
char dirPath[256];
char dirTimeBuf[256];
time_t dirTime = 0;
char mergeUnitStr[256];
int mergeUnit = 0;

// KYU: test for unit integration
int num_org_unit_entry = 0;
int num_unit_entry = 0;
FILE *testout;
long ignored_log=0;

// UBSI Unit analysis
#include <assert.h>

thread_group_leader_t *thread_group_leader_hash;
thread_group_t *thread_group_hash;
// Maximum iterations that can be buffered during a single timestamp
#define iteration_count_buffer_size 1000
// Total number of iterations so far in the iteration_count buffer
int current_time_iterations_index = 0;
// A buffer to keep iteration_count objects for iterations
iteration_count_t current_time_iterations[iteration_count_buffer_size];
// To keep track of whenever the timestamp changes on audit records
double last_time = -1;

// A list of thread start times for each pid seen being created
thread_time_t *thread_create_time;
// A flag to indicate that only a single file is to be processed with 'F' flag
bool singleFile = FALSE;

unit_table_t *unit_table;
event_buf_t *event_buf = NULL;

bool incomplete_record = false;

void syscall_handler(char *buf);
int get_max_pid();
void kyu_test(int max_pid);


// KYU: Test UNIT integration
typedef struct stats{
		long num_unit_syscall;
		long num_unit_imp_syscall;
		long num_unit_no_syscall;
		long total_syscall;
		long total_imp_syscall;
		long num_unit_no_dep;
		long num_unit_dep;
		long total_dep;
} stats;

stats s;
/*
			Java does not support reading from Unix domain sockets.

			This utility reads audit records from the audispd socket and writes them
			to the standard output stream.

			The Audit Reporter can invoke this utility and read from its standard
			output to obtain a stream of audit records.
	*/

void print_usage(char** argv) {
		printf("Usage: %s [OPTIONS]\n", argv[0]);
		printf("  -u, --unit                unit analysis\n");
		printf("  -s, --socket              socket name\n");
		printf("  -w, --wait-for-end        continue processing till the end of the log is reached\n");
		printf("  -f, --files               a filename that has a list of log files to process\n");  
		printf("  -F, --file				single file to process\n");  
		printf("  -d, --dir                 a directory name that contains log files\n");
		printf("  -t, --time                timestamp. Only handle log files modified after the timestamp. \n");
		printf("  -m, --merge-unit          merge N units into a single unit.\n");
		printf("                            This option is only valid with -d option. (format: YYYY-MM-DD:HH:MM:SS,\n");
		printf("                              e.g., 2017-1-21:07:09:20)\n");
		printf("  -c, --csv                 export output in CSV format.\n");
		printf("  -h, --help                print this help and exit\n");
		printf("\n");

}

int command_line_option(int argc, char **argv)
{
		int c;

		struct option   long_opt[] =
		{
				{"help",			no_argument,		NULL, 'h'},
				{"unit",			no_argument,		NULL, 'u'},
				{"socket",			required_argument,	NULL, 's'},
				{"files",			required_argument,	NULL, 'f'},
				{"file",			required_argument,	NULL, 'F'},
				{"dir",				required_argument,	NULL, 'd'},
				{"time",			required_argument,	NULL, 't'},
				{"wait-for-end",	no_argument,		NULL, 'w'},
				{"merge-unit",	required_argument,		NULL, 'm'},
				{"csv",	required_argument,		NULL, 'c'},
				{NULL,				0,					NULL,	0}
		};

		while((c = getopt_long(argc, argv, "hcus:F:f:d:t:m:w", long_opt, NULL)) != -1)
		{
				switch(c)
				{
						case 's':
								strncpy(socketPath, optarg, 256);
								socketRead = TRUE;
								break;
						case 'f':
								strncpy(filePath, optarg, 256);
								fileRead = TRUE;
								break;
						case 'F':
								strncpy(filePath, optarg, 256);
								fileRead = TRUE;
								singleFile = TRUE;
								break;
						case 'd':
								strncpy(dirPath, optarg, 256);
								dirRead = TRUE;
								break;
						case 'm':
								strncpy(mergeUnitStr, optarg, 256);
								mergeUnit = atoi(mergeUnitStr);
								break;

						case 't':
								strncpy(dirTimeBuf, optarg, 256);
								struct tm temp_tm;
								if(strptime(dirTimeBuf, "%Y-%m-%d:%H:%M:%S", &temp_tm) == 0) {
										fprintf(stderr, "time error: %s, dirTime = %ld\n", dirTimeBuf, dirTime);
										break;
								}
							 dirTime = mktime(&temp_tm);
								fprintf(stderr, "dirTime = %ld\n", dirTime);
								break;

						case 'w':
								waitForEnd = TRUE;
								break;

						case 'u':
								UBSIAnalysis = TRUE;
								break;

						case 'c':
								CSVOUT = TRUE;
								break;

						case 'h':
								print_usage(argv);
								exit(0);

						default:
								fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);
								exit(-2);
				};
		};

}

void socket_read(char *programName)
{
		int audispdSocketDescriptor = -1, charactersRead, bytesReceived;
		char buffer[BUFFER_LENGTH];
		struct sockaddr_un serverAddress;

		do {
				audispdSocketDescriptor = socket(AF_UNIX, SOCK_STREAM, 0);
				if (audispdSocketDescriptor < 0) {
						fprintf(stderr, "%s: Unable to construct a socket. Error: %s\n", programName, strerror(errno));
						break;
				}

				memset(&serverAddress, 0, sizeof (serverAddress));
				serverAddress.sun_family = AF_UNIX;
				strcpy(serverAddress.sun_path, socketPath);

				charactersRead = connect(audispdSocketDescriptor, (struct sockaddr *) &serverAddress, SUN_LEN(&serverAddress));
				if (charactersRead < 0) {
						fprintf(stderr, "%s: Unable to connect to the socket: %s. Error: %s\n", programName, socketPath, strerror(errno));
						break;
				}

				fprintf(stderr, "#CONTROL_MSG#pid=%d\n", getpid());

				while (TRUE) {
						memset(&buffer, 0, BUFFER_LENGTH);
						charactersRead = recv(audispdSocketDescriptor, & buffer[0], BUFFER_LENGTH - 1, 0);
						if (charactersRead < 0) {
								fprintf(stderr, "%s: Error while reading from the socket. Error: %s\n", programName, strerror(errno));
								break;
						} else if (charactersRead == 0) {
								fprintf(stderr, "%s: Server closed the connection. Errror: %s\n", programName, strerror(errno));
								break;
						}
						UBSI_buffer(buffer);
				}
		} while (FALSE);

		if (audispdSocketDescriptor != -1) close(audispdSocketDescriptor);
}

void read_log(FILE *fp, const char* filepath)
{
		char buffer[BUFFER_LENGTH];

		fprintf(stderr, "#CONTROL_MSG#pid=%d\n", getpid());
		do{
				while (TRUE) {
						memset(&buffer, 0, BUFFER_LENGTH);
						if(fgets(& buffer[0], BUFFER_LENGTH, fp) == NULL) {
								fprintf(stderr, "Reached the end of file (%s).\n", filepath);
								UBSI_buffer_flush();
								break;
						}
						UBSI_buffer(buffer);
				}
		} while (FALSE);
}

void read_file_path()
{
	// If 'F' flag was passed
	if(singleFile == TRUE){
		
		FILE *log_fp;
		fprintf(stderr, "reading a log file: %s", filePath);
		
		log_fp = fopen(filePath, "r");
		if(log_fp == NULL) {
				fprintf(stderr, "file open error: %s", filePath);
		}

		read_log(log_fp, filePath);
		fclose(log_fp);
		UBSI_buffer_flush();
		
	}else{ // If 'f' flag was passed
	
		FILE *fp = fopen(filePath, "r");
		FILE *log_fp;
		char tmp[1024];
		char buffer[BUFFER_LENGTH];

		if(fp == NULL) {
				fprintf(stderr, "file open error: %s\n", filePath);
				return;
		}

		while(!feof(fp)) {
				if(fgets(tmp, 1024, fp) == NULL) break;
				fprintf(stderr, "reading a log file: %s", tmp);
				if(tmp[strlen(tmp)-1] == '\n') tmp[strlen(tmp)-1] = '\0';
				
				log_fp = fopen(tmp, "r");
				if(log_fp == NULL) {
						fprintf(stderr, "file open error: %s", tmp);
						continue;
				}

				read_log(log_fp, tmp);
				fclose(log_fp);
		}

		UBSI_buffer_flush();
		fclose(fp);
	}
}

ino_t find_next_file(time_t time, ino_t cur_inode)
{
		DIR *d;
		struct dirent *dir;
		char file[1024];
		struct stat sbuf;
		char time_buf[256];
		struct tm tm;
		
		char eFile[1024];
		time_t eTime = 0; // the earliest file mod time but later than dirTime
		long eInode = 0;

		d = opendir(dirPath);

		if(d == NULL) {
				fprintf(stderr, "dir open error: %s\n", dirPath);
				return -1;
		}

		//strftime(time_buf, sizeof(time_buf), "%Y-%m-%d:%H:%M:%S", localtime(&time));
		//printf("DirTime %s(%ld)\n", time_buf, time);

		while((dir = readdir(d)) != NULL)
		{
				sprintf(file, "%s/%s", dirPath, dir->d_name);
				if(stat(file, &sbuf) == -1) {
						//fprintf(stderr, "stat error 1: %s\n", file);
						//fprintf(stderr, "errno %d\n", errno);
						continue;
				}
				if(!S_ISREG(sbuf.st_mode)) continue; // if the file is not a regular file (e.g., dir)
				
				if(sbuf.st_mtime > time)
				{
						if(cur_inode == sbuf.st_ino) continue; // this is current file.
						if(eTime == 0 || sbuf.st_mtime < eTime) {
								eTime = sbuf.st_mtime;
								eInode = sbuf.st_ino;
						}
				}
//				strftime(time_buf, sizeof(time_buf), "%Y-%m-%d:%H:%M:%S", localtime(&sbuf.st_mtime));
//				printf("file: %s, last modified time %s(%ld)\n", file, time_buf, sbuf.st_mtime);
		}
		
		if(eInode > 0) {
//				strftime(time_buf, sizeof(time_buf), "%Y-%m-%d:%H:%M:%S", localtime(&eTime));
//				printf("Read next file: (inode %d, last modified time %s(%ld)\n", eInode, time_buf, eTime);
		} 
		closedir(d);
		return eInode;
}

FILE *open_inode(ino_t inode)
{
		DIR *d;
		struct dirent *dir;
		char file[1024];
		struct stat sbuf;
		FILE *fp;

		d = opendir(dirPath);

		if(d == NULL) {
				fprintf(stderr, "dir open error: %s\n", dirPath);
				return NULL;
		}

		while((dir = readdir(d)) != NULL)
		{
				sprintf(file, "%s/%s", dirPath, dir->d_name);
				if(stat(file, &sbuf) == -1) {
						fprintf(stderr, "stat error 2: %s\n", file);
						continue;
				}
				if(sbuf.st_ino == inode) {
						fp = fopen(file, "r");
						closedir(d);
						return fp;
				}
		}

		closedir(d);
		return NULL;
}

ino_t read_log_online(ino_t inode)
{
		char buffer[BUFFER_LENGTH];
		struct stat sbuf;
		time_t time;

		FILE *fp = open_inode(inode);
		
		if(fp == NULL) {
				fprintf(stderr, "file open error 1: inode %ld\n", inode);
				return -1;
		}
		
		do{
				while (TRUE) {
						memset(&buffer, 0, BUFFER_LENGTH);
						while(fgets(& buffer[0], BUFFER_LENGTH, fp) == NULL) {

								if(fstat(fileno(fp), &sbuf) == -1) {
										fprintf(stderr, "stat fails: inode %ld\n", inode);
										continue;
								}
								time = sbuf.st_mtime;
								ino_t next_inode = find_next_file(time, sbuf.st_ino);
								if(next_inode  > 0) {
										while(fgets(& buffer[0], BUFFER_LENGTH, fp) != NULL) { // check the log again.
												UBSI_buffer(buffer);
										}
										// At this point, the next log is available and the current log does not have any new event. 
										//Safe to close the current one and process the next log
										fclose(fp); 
										return next_inode;
								}
						}
						UBSI_buffer(buffer);
				}
		} while (FALSE);
}

void dir_read()
{
		ino_t inode = 0;
		
		fprintf(stderr, "#CONTROL_MSG#pid=%d\n", getpid());
		
		while((inode = find_next_file(dirTime, 0)) <= 0) sleep(1);
		//printf("Next file: inode %ld\n", inode);

		while((inode = read_log_online(inode)) > 0)
		{
				//printf("Next file: inode %ld\n", inode);
		}
}

int main(int argc, char *argv[]) {
		int max_pid, i;
		char *programName = argv[0];
		int audispdSocketDescriptor = -1, charactersRead, bytesReceived;
		char buffer[BUFFER_LENGTH];
		struct sockaddr_un serverAddress;

		// KYU TEST
		testout = fopen("./testout", "w");

		putenv("TZ=EST5EDT"); // set timezone
		tzset();

		command_line_option(argc, argv);

		signal(SIGINT, UBSI_sig_handler);
		signal(SIGKILL, UBSI_sig_handler);
		signal(SIGTERM, UBSI_sig_handler);
		
		//fprintf(stderr, "mergeUnit = %d\n", mergeUnit);
		max_pid = get_max_pid() + 1;
		max_pid = max_pid*2;
		thread_create_time = new thread_time_t[max_pid]();
		for(i = 0; i < max_pid; i++) {
				thread_create_time[i].seconds = 0;
				thread_create_time[i].milliseconds = 0;
		}

		if(socketRead) socket_read(programName);
		else if(fileRead) read_file_path();
		else if(dirRead) dir_read();
		else read_log(stdin, "stdin");
		
		kyu_test(max_pid); //KYU: test unit integration
		fclose(testout);
		return 0;
}

/*
 * Checks if an iteration exists with the arguments provided
 * 
 * If exists, then increments the count for it and returns that count.
 * If doesn't exist then adds this iteration_count and returns the count
 * value which would be zero.
 */
int get_iteration_count(int tid, int unitid, int iteration){
	int count = -1;
	// Check if the iteration exists
	if(current_time_iterations_index != 0){
			int a = 0;
			for(; a<current_time_iterations_index; a++){
					if(current_time_iterations[a].tid == tid 
							&& current_time_iterations[a].unitid == unitid
								&& current_time_iterations[a].iteration == iteration){
							current_time_iterations[a].count++;
							// if found then increment the count and set that count to the return value
							count = current_time_iterations[a].count;
							break;
					}
			}
	}
	// If not found then try to add it
	if(count == -1){
		// If buffer already full then print an error. -1 would be returned
		if(current_time_iterations_index >= iteration_count_buffer_size){
			fprintf(stderr, "Not enough space for another iteration. Increase 'iteration_count_buffer_size' and rerun\n");
		}else{
			// Add to the end of the buffer and set the count to the return value
			// without incrementing (counts start from 0)
			current_time_iterations[current_time_iterations_index].tid = tid;
			current_time_iterations[current_time_iterations_index].unitid = unitid;
			current_time_iterations[current_time_iterations_index].iteration = iteration;
			current_time_iterations[current_time_iterations_index].count = 0;
			count = current_time_iterations[current_time_iterations_index].count;
			current_time_iterations_index++;
		}
	}
	return count;
}

// Just resets the index instead of resetting each individual struct in the buffer
// Starts overriding the structs from the previous timestamp
void reset_current_time_iteration_counts(){
	current_time_iterations_index = 0;	
}

bool is_same_unit(thread_unit_t u1, thread_unit_t u2)
{
		if(u1.tid == u2.tid && 
				 u1.thread_time.seconds == u2.thread_time.seconds &&
				 u1.thread_time.milliseconds == u2.thread_time.milliseconds &&
					u1.loopid == u2.loopid &&
					u1.iteration == u2.iteration &&
					u1.timestamp == u2.timestamp &&
					u1.count == u2.count) return true;

		return false;
}

void get_time_and_eventid(char *buf, double *time, long *eventId)
{
		// Expected string format -> "type=<TYPE> msg=audit(<TIME>:<EVENTID>): ...."
		char *ptr;

		ptr = strstr(buf, "(");
		if(ptr == NULL) {
				incomplete_record = true;
				return;
		}

		sscanf(ptr+1, "%lf:%ld", time, eventId);

		return;

}

double get_timestamp_double(char *buf){
		char *ptr;
		double time;
		ptr = strstr(buf, "(");
		if(ptr == NULL) {
				incomplete_record = true;
				return 0;
		}

		sscanf(ptr+1, "%lf", &time);

		return time;
}

void get_timestamp(char *buf, int* seconds, int* millis)
{
		char *ptr;
// record format: 'type=X msg=audit(123.456:890): ...' OR 'type=X msg=ubsi(123.456:890): ...'
		ptr = strstr(buf, "(");
		if(ptr == NULL){
			*seconds = -1;
			*millis = -1;
		 incomplete_record = true;
		}else{
			sscanf(ptr+1, "%d", seconds);
			
			ptr = strstr(buf, ".");
			if(ptr == NULL){
				*seconds = -1;
				*millis = -1;
				incomplete_record = true;
			}else{
				sscanf(ptr+1, "%d", millis);
			}
		}
}

// Reads timestamp from audit record and then sets the seconds and milliseconds to the thread_time struct ref passed
void set_thread_time(char *buf, thread_time_t* thread_time)
{
		get_timestamp(buf, &thread_time->seconds, &thread_time->milliseconds);
}

void set_thread_seen_time_conditionally(int pid, char* buf){
		thread_time_t* thread_time;
		thread_time = &thread_create_time[pid];
		if(thread_time->seconds == 0 && thread_time->milliseconds == 0){ // 0 means not set before
				set_thread_time(buf, thread_time);
		}
}

long get_eventid(char* buf){
		char *ptr;
		long eventId;

		// Expected string format -> "type=<TYPE> msg=audit(<TIME>:<EVENTID>): ...."
		ptr = strstr(buf, ":");
		if(ptr == NULL) {
				incomplete_record = true;
				return 0;
		}

		sscanf(ptr+1, "%ld", &eventId);

		return eventId;
}

int emit_log(unit_table_t *ut, char* buf, bool print_unit, bool print_proc)
{
		if(incomplete_record == true) return 0;
		if(print_proc && ut->proc[0] == '\0') return 0;
		int rc = 0;

		if(!print_unit && !print_proc) {
				rc = printf("%s", buf);
				return rc;
		}

		buf[strlen(buf)-1] = '\0';
		
		rc = printf("%s", buf);
		if(print_unit) {
				rc += printf(" unit=(pid=%d thread_time=%d.%03d unitid=%d iteration=%d time=%.3lf count=%d) "
							,ut->cur_unit.tid, ut->thread.thread_time.seconds, ut->thread.thread_time.milliseconds, ut->cur_unit.loopid, ut->cur_unit.iteration, ut->cur_unit.timestamp, ut->cur_unit.count);
		} 

		if(print_proc) {
				rc += printf("%s", ut->proc);
		}

		if(!print_proc) rc += printf("\n");

		return rc;
}

void delete_unit_id_map(unit_id_map_t *unit_map)
{
		unit_id_map_t *tmp_id, *cur_id;

		if(unit_map != NULL) {
				HASH_ITER(hh, unit_map, cur_id, tmp_id) {
						HASH_DEL(unit_map, cur_id); 
						if(cur_id) delete cur_id;
				}
		}
}

void delete_unit_hash(link_unit_t *hash_unit, mem_unit_t *hash_mem)
{
		link_unit_t *tmp_unit, *cur_unit;
		mem_unit_t *tmp_mem, *cur_mem;

		HASH_ITER(hh, hash_unit, cur_unit, tmp_unit) {
				HASH_DEL(hash_unit, cur_unit); 
				if(cur_unit) delete cur_unit;
		}
}

void delete_proc_hash(mem_proc_t *mem_proc)
{
		mem_proc_t *tmp_mem, *cur_mem;
		HASH_ITER(hh, mem_proc, cur_mem, tmp_mem) {
				HASH_DEL(mem_proc, cur_mem); 
				if(cur_mem) delete cur_mem;
		}
}

void loop_entry(unit_table_t *unit, long a1, char* buf, double time)
{
		char *ptr;

		unit->cur_unit.loopid = a1;
		unit->cur_unit.iteration = 0;
		unit->cur_unit.timestamp = time;
		
		ptr = strstr(buf, " ppid=");
		if(ptr == NULL) {
				fprintf(stderr, "loop_entry error! cannot find proc info: %s", buf);
				incomplete_record = true;
		} else {
				ptr++;
				strncpy(unit->proc, ptr, strlen(ptr));
				unit->proc[strlen(ptr)] = '\0';
		}
}

void loop_exit(unit_table_t *unit, char *buf)
{
		char tmp[10240];
		double time;
		long eventId;

		get_time_and_eventid(buf, &time, &eventId);
		// Adding extra space at the end of UBSI_EXIT string below because last character is overwritten with NULL char
		if(incomplete_record == false && unit->proc[0] != '\0') {
				if(CSVOUT) {
						CSV_UBSI(unit, buf, "UBSI_EXIT", NULL, NULL);
				} else {
						sprintf(tmp, "type=UBSI_EXIT msg=ubsi(%.3f:%ld):  ", time, eventId);
						emit_log(unit, tmp, false, true);
				}
				unit->valid = false;
		}
}

void unit_entry(unit_table_t *unit, long a1, char* buf)
{
		char tmp[10240];
		int tid = unit->thread.tid;
		double time;
		long eventid;

		time = get_timestamp_double(buf);
		eventid = get_eventid(buf);

		if(last_time == -1){
			last_time = time;	
		}else if(last_time != time){
			last_time = time;
			reset_current_time_iteration_counts();
		}

		if(unit->valid == false) // this is an entry of a new loop.
		{
				loop_entry(unit, a1, buf, time);
		} else {
				unit->cur_unit.iteration++;
		}
		unit->valid = true;
		unit->cur_unit.timestamp = time;
		
		int iteration_count_value = get_iteration_count(tid, 
												unit->cur_unit.loopid,
												unit->cur_unit.iteration);
		// Can return -1 which means that the buffer is full. Error printed in 
		// get_iteration_count function
		unit->cur_unit.count = iteration_count_value;
		
		if(incomplete_record == false && unit->proc[0] != '\0') {
				if(CSVOUT) {
						CSV_UBSI(unit, buf, "UBSI_ENTRY", NULL, NULL);
				} else {
						sprintf(tmp, "type=UBSI_ENTRY msg=ubsi(%.3f:%ld): ", time, eventid);
						emit_log(unit, tmp, true, true);
				}
		}
		if(mergeUnit > 0) {
				unit->merge_count = 1;
		}
}

void unit_entry_map_uid(unit_table_t *ut, long a1, char* buf)
{
		ut->unitid = a1;
		// find main thread
		int pid = ut->pid;
		unit_table_t *pt;

		if(pid == ut->thread.tid) pt = ut;
		else {
				thread_t th;  
				th.tid = pid; 
				th.thread_time.seconds = thread_create_time[pid].seconds;
				th.thread_time.milliseconds = thread_create_time[pid].milliseconds;
				HASH_FIND(hh, unit_table, &th, sizeof(thread_t), pt); 
				//HASH_FIND_INT(unit_table, &pid, pt);
				if(pt == NULL) {
						fprintf(stderr, "UENTRY_ID NULL, id = %ld\n", a1);
						incomplete_record = true;
						return;
				}
		}

		unit_id_map_t *umap = new unit_id_map_t();
		assert(umap);
		umap->unitid = (int)a1;
		umap->thread_unit = ut->cur_unit;
		HASH_ADD(hh, pt->unit_id_map, unitid, sizeof(int), umap);
	/*	fprintf(stderr, "UENTRY_ID added, :%ld, pid %d, uid %ld(%x) (pt->unit_id_map %p)\n", get_eventid(buf), pid, a1, a1, pt->unit_id_map);

		unit_id_map_t *umap_t;
		int unitid = (int)a1;
		HASH_FIND(hh, pt->unit_id_map, &unitid, sizeof(int), umap_t);
		if(umap_t == NULL) {
				fprintf(stderr, "UENTRY_ID failed!, pid %d, uid %ld(%x) (pt->unit_id_map %p) \n", pid, unitid, unitid, pt->unit_id_map);
		} else {
				fprintf(stderr, "UENTRY_ID succeed!, pid %d, uid %ld(%x) (pt->unit_id_map %p) \n", pid, unitid, unitid, pt->unit_id_map);
		}*/
}

void unit_end(unit_table_t *unit, long a1)
{
		if(unit == NULL) return;
		struct link_unit_t *ut;
		char *buf;
		int buf_size;

		delete_unit_hash(unit->link_unit, unit->mem_unit);
		unit->link_unit = NULL;
		unit->mem_unit = NULL;
		unit->r_addr = 0;
		unit->w_addr = 0;
		unit->merge_count = 0;

		/* KYU: test for unit integration */
		unit->new_dep = 0;
		unit->num_proc_syscall = 0;
		unit->num_io_syscall = 0;
		unit->num_syscall = 0;
		/* KYU: test for unit integration */
}

void clear_proc(unit_table_t *unit)
{
	// printf("In clear proc. %d\n", unit->pid);
		if(unit == NULL) return;

		unit_end(unit, -1);
		delete_proc_hash(unit->mem_proc);
		delete_unit_id_map(unit->unit_id_map);
		unit->mem_proc = NULL;
		unit->unit_id_map = NULL;

		//KYU: unit integration
		fd_t *cur_fd, *tmp_fd;
		HASH_ITER(hh, unit->fd, cur_fd, tmp_fd) {
				HASH_DEL(unit->fd, cur_fd);
				if(cur_fd) delete cur_fd;
		}
		unit->fd = NULL;
		//KYU: unit integration
		// printf("out clear proc. %d\n", unit->pid);
}

void proc_end(unit_table_t *unit)
{
	// printf("In proc end. %d\n", unit->pid);
		if(unit == NULL) return;

		thread_group_leader_t *tgl;
		HASH_FIND(hh, thread_group_leader_hash, &(unit->thread), sizeof(thread_t), tgl);
		if(tgl) {
				HASH_DEL(thread_group_leader_hash, tgl);
				delete tgl;
		}

		clear_proc(unit);
		// printf("before table del. %d, %d, %d\n", unit->pid, unit->thread.tid, unit->ppid);
		
		HASH_DEL(unit_table, unit);
		delete unit;

		// printf("out proc end. %d, %d, %d\n", unit->pid, unit->thread.tid, unit->ppid);
		return;
}

void proc_group_end(unit_table_t *unit)
{
		int pid = unit->pid;
		unit_table_t *pt;

		thread_group_leader_t *tgl;
		thread_group_t *tg;
		thread_hash_t *cur_t, *tmp_t;
		unit_table_t *ut;

		HASH_FIND(hh, thread_group_leader_hash, &(unit->thread), sizeof(thread_t), tgl);
		if(tgl == NULL) return;
		
		HASH_FIND(hh, thread_group_hash, &(tgl->leader), sizeof(thread_t), tg);
		if(tg == NULL)	return;
		

		HASH_ITER(hh, tg->threads, cur_t, tmp_t) {
				HASH_FIND(hh, unit_table, &(cur_t->thread), sizeof(thread_t), ut); 
				proc_end(ut);
				HASH_DEL(tg->threads, cur_t);
				delete cur_t;
		}

		HASH_FIND(hh, unit_table, &(tgl->thread), sizeof(thread_t), ut); 
		proc_end(ut);

		HASH_DEL(thread_group_hash, tg);
		delete tg;
}

void flush_all_unit()
{
		unit_table_t *tmp_unit, *cur_unit;
		HASH_ITER(hh, unit_table, cur_unit, tmp_unit) {
				unit_end(cur_unit, -1);
		}
}

void mem_write(unit_table_t *ut, long int addr, char* buf)
{
		if(ut->cur_unit.loopid == 0 || ut->cur_unit.timestamp == 0) return;
		// check for dup_write
		mem_unit_t *umt;
		HASH_FIND(hh, ut->mem_unit, &addr, sizeof(long int), umt);

		if(umt != NULL) {
				//fprintf(stderr, "umt is not null: %lx\n", addr);
				return;
		}

		// not duplicated write
		umt = new mem_unit_t();
		assert(umt);
		umt->addr = addr;
		HASH_ADD(hh, ut->mem_unit, addr, sizeof(long int),  umt);

		// add it into process memory map
		int pid = ut->pid;
		unit_table_t *pt;
		if(pid == ut->thread.tid) pt = ut;
		else {
				thread_t th;  
				th.tid = pid; 
				th.thread_time.seconds = thread_create_time[pid].seconds;
				th.thread_time.milliseconds = thread_create_time[pid].milliseconds;
				HASH_FIND(hh, unit_table, &th, sizeof(thread_t), pt); 
				//HASH_FIND_INT(unit_table, &pid, pt);
				if(pt == NULL) {
						return;
				}
		}

		mem_proc_t *pmt;
		HASH_FIND(hh, pt->mem_proc, &addr, sizeof(long int), pmt);
		if(pmt == NULL) {
				pmt = new mem_proc_t();
				assert(pmt);
				pmt->addr = addr;
				pmt->last_written_unit = ut->cur_unit;
				HASH_ADD(hh, pt->mem_proc, addr, sizeof(long int),  pmt);
		} else {
				pmt->last_written_unit = ut->cur_unit;
		}
}

void mem_read(unit_table_t *ut, long int addr, char *buf)
{
		if(ut->cur_unit.loopid == 0 || ut->cur_unit.timestamp == 0) return;

		int pid = ut->pid;
		unit_table_t *pt;
		char tmp[2048];
		double time;
		long eventId;

		if(pid == ut->thread.tid) pt = ut;
		else {
				thread_t th;  
				th.tid = pid; 
				th.thread_time.seconds = thread_create_time[pid].seconds;
				th.thread_time.milliseconds = thread_create_time[pid].milliseconds;
				HASH_FIND(hh, unit_table, &th, sizeof(thread_t), pt); 
				//HASH_FIND_INT(unit_table, &pid, pt);
				if(pt == NULL) {
						return;
				}
		}

		mem_proc_t *pmt;
		HASH_FIND(hh, pt->mem_proc, &addr, sizeof(long int), pmt);
		if(pmt == NULL) return;

		thread_unit_t lid;
		if(pmt->last_written_unit.timestamp != 0 && !is_same_unit(pmt->last_written_unit, ut->cur_unit))
		{
				link_unit_t *lt;
				lid = pmt->last_written_unit;
				HASH_FIND(hh, ut->link_unit, &lid, sizeof(thread_unit_t), lt);
				if(lt == NULL) {
						// emit the dependence.
						lt = new link_unit_t();
						assert(lt);
						lt->id = pmt->last_written_unit;
						HASH_ADD(hh, ut->link_unit, id, sizeof(thread_unit_t), lt);

						get_time_and_eventid(buf, &time, &eventId);
						if(incomplete_record == false && ut->proc[0] != '\0') {
								if(CSVOUT) {
										char tmp2[2048];
										sprintf(tmp, "%d_%d.%03d",lt->id.tid, lt->id.thread_time.seconds, lt->id.thread_time.milliseconds);
										sprintf(tmp2, "%.3lf_%d_%d", lt->id.timestamp, lt->id.loopid, lt->id.iteration);
										CSV_UBSI(ut, buf, "UBSI_DEP", tmp, tmp2);
								} else {
										sprintf(tmp, "type=UBSI_DEP msg=ubsi(%.3f:%ld): dep=(pid=%d thread_time=%d.%03d unitid=%d iteration=%d time=%.3lf count=%d), "
														,time, eventId, lt->id.tid, lt->id.thread_time.seconds, lt->id.thread_time.milliseconds, lt->id.loopid, lt->id.iteration, lt->id.timestamp, lt->id.count);
										emit_log(ut, tmp, true, true);
								}
								ut->new_dep++; // KYU: test for unit integration
						}
				}
		}
}

void UBSI_dep(unit_table_t *ut, long unit_from, char *buf)
{
		long eventId;
		int pid = ut->pid;
		unit_table_t *pt;
		char tmp[2048];
		double time;

		if(pid == ut->thread.tid) pt = ut;
		else {
				thread_t th;  
				th.tid = pid; 
				th.thread_time.seconds = thread_create_time[pid].seconds;
				th.thread_time.milliseconds = thread_create_time[pid].milliseconds;
				HASH_FIND(hh, unit_table, &th, sizeof(thread_t), pt); 
				//HASH_FIND_INT(unit_table, &pid, pt);
				if(pt == NULL) {
						incomplete_record = true;
						fprintf(stderr, "UDEP, pt is null!\n");
						return;
				}
		}

		unit_id_map_t *umap_t;
		int unitid = (int)unit_from;
		HASH_FIND(hh, pt->unit_id_map, &unitid, sizeof(int), umap_t);
		if(umap_t == NULL) {
				//fprintf(stderr, "UDEP, umap is null!, unitfrom = pid %d, %d(%x) (pt->unit_id_map %p) \n", pid, unitid, unitid, pt->unit_id_map);
				//fprintf(stderr, "      %s\n", buf);
				return;
		}
				
		if(is_same_unit(ut->cur_unit, umap_t->thread_unit)) return; 

		link_unit_t *lt;
		thread_unit_t lid = umap_t->thread_unit;
		HASH_FIND(hh, ut->link_unit, &lid, sizeof(thread_unit_t), lt);
		if(lt != NULL)  return; // this dependency has already emitted

		lt = new link_unit_t();
		assert(lt);
		lt->id = umap_t->thread_unit;
		HASH_ADD(hh, ut->link_unit, id, sizeof(thread_unit_t), lt);

		get_time_and_eventid(buf, &time, &eventId);

		if(CSVOUT) {
				char tmp2[2048];
				sprintf(tmp, "%d_%d.%03d",umap_t->thread_unit.tid, umap_t->thread_unit.thread_time.seconds, umap_t->thread_unit.thread_time.milliseconds);
				sprintf(tmp2, "%.3lf_%d_%d", umap_t->thread_unit.timestamp, umap_t->thread_unit.loopid, umap_t->thread_unit.iteration);
				CSV_UBSI(ut, buf, "UBSI_DEP", tmp, tmp2);
		} else {
				sprintf(tmp, "type=UBSI_DEP msg=ubsi(%.3f:%ld): dep=(pid=%d thread_time=%d.%03d unitid=%d iteration=%d time=%.3lf count=%d), "
								,time, eventId, umap_t->thread_unit.tid, umap_t->thread_unit.thread_time.seconds, umap_t->thread_unit.thread_time.milliseconds, umap_t->thread_unit.loopid, umap_t->thread_unit.iteration, umap_t->thread_unit.timestamp, umap_t->thread_unit.count);
				emit_log(ut, tmp, true, true);
		}
		ut->new_dep++; // KYU: test for unit integration
  
		//ut->num_dep++;
		//sprintf(tmp, "type=UBSI_DEP msg=ubsi(%.3f:%ld): dep=(%d-%d)" ,time, eventId, ut->unitid, unit_from);
		//emit_log(ut, tmp, true, true);
}

unit_table_t* add_unit(int tid, int pid, bool valid, char *buf)
{
		int i;
		struct unit_table_t *ut;
		ut = new unit_table_t();
		assert(ut);
		ut->thread.tid = tid;
		ut->thread.thread_time.seconds = thread_create_time[tid].seconds;
		ut->thread.thread_time.milliseconds = thread_create_time[tid].milliseconds;
		ut->pid = pid;
		ut->valid = valid;
		ut->merge_count = 0;

		ut->cur_unit.tid = tid;
		ut->cur_unit.thread_time.seconds = thread_create_time[tid].seconds;
		ut->cur_unit.thread_time.milliseconds = thread_create_time[tid].milliseconds;
		ut->cur_unit.loopid = 0;
		ut->cur_unit.iteration = 0;
		ut->cur_unit.timestamp = 0;
		ut->cur_unit.count = 0; 

		ut->link_unit = NULL;
		ut->mem_proc = NULL;
		ut->mem_unit = NULL;
		ut->unit_id_map = NULL;

		/* KYU: test for unit integration */
		ut->new_dep = 0;
		ut->num_proc_syscall = 0;
		ut->num_io_syscall = 0;
		ut->num_syscall = 0;
		ut->fd = NULL;
		/* KYU: test for unit integration */

		/* support OQL*/
		if(extract_int(buf, " ppid=", &(ut->ppid)) == 0) ut->ppid = -1;
		if(extract_int(buf, " gid=", &(ut->gid)) == 0) ut->gid = -1;
		if(extract_int(buf, " uid=", &(ut->uid)) == 0) ut->uid = -1;
		if(extract_int(buf, " euid=", &(ut->euid)) == 0) ut->euid = -1;
		string comm = extract_string(buf, " comm=");
		string exe = extract_string(buf, " exe=");
		comm.copy(ut->comm, 1024);
		exe.copy(ut->exe, 1024);

		//printf("add_unit: tid %d, pid %d, ppid %d, gid %d, uid %d, euid %d, comm=%s, exe=%s\n", ut->thread.tid, ut->pid, ut->ppid, ut->gid, ut->uid, ut->euid, ut->comm, ut->exe);
		/* support OQL*/

		bzero(ut->proc, 1024);
		for(i = 0; i < MAX_SIGNO; i++) {
				ut->signal_handler[i] = false;
		}
		HASH_ADD(hh, unit_table, thread, sizeof(thread_t), ut);
		return ut;
}

void set_thread_group(thread_t leader, thread_t child)
{
		thread_group_t *ut;
		thread_hash_t *lt;

		HASH_FIND(hh, thread_group_hash, &leader, sizeof(thread_t), ut);
		if(ut == NULL) {
				ut = new thread_group_t();
				assert(ut);
				ut->leader = leader;
				ut->threads = NULL;

				lt = new thread_hash_t();
				assert(lt);
				lt->thread = child;
				HASH_ADD(hh, ut->threads, thread, sizeof(thread_t), lt);

				HASH_ADD(hh, thread_group_hash, leader, sizeof(thread_t), ut);
		} else {
				HASH_FIND(hh, ut->threads, &child, sizeof(thread_t), lt);
				if(lt == NULL) {
						lt = new thread_hash_t();
						assert(lt);
						lt->thread = child;
						HASH_ADD(hh, ut->threads, thread, sizeof(thread_t), lt);
				}
		}
}

thread_group_leader_t* add_thread_group_leader(thread_t thread, thread_t leader)
{
		thread_group_leader_t *ut = new thread_group_leader_t();
		assert(ut);
		ut->thread = thread;
		ut->leader = leader;
		
		HASH_ADD(hh, thread_group_leader_hash, thread, sizeof(thread_t), ut);

		return ut;
}

void set_thread_group_leader(thread_t child, thread_t parent)
{
		thread_group_leader_t *ut;
		HASH_FIND(hh, thread_group_leader_hash, &child, sizeof(thread_t), ut);

		if(ut != NULL) return; // child is already in the hash

		HASH_FIND(hh, thread_group_leader_hash, &parent, sizeof(thread_t), ut);
		if(ut == NULL) {
				// parent is not in the hash
				ut = add_thread_group_leader(parent, parent);
		}
		
		ut = add_thread_group_leader(child, ut->leader);

		set_thread_group(ut->leader, child);
}

void set_pid(int tid, int pid, char* buf)
{
		struct unit_table_t *ut;
		int ppid;

		thread_t th_child, th_parent; 
		th_parent.tid = pid; 
		th_parent.thread_time.seconds = thread_create_time[pid].seconds;
		th_parent.thread_time.milliseconds = thread_create_time[pid].milliseconds;
		HASH_FIND(hh, unit_table, &th_parent, sizeof(thread_t), ut);  /* looking for parent thread's pid */

		if(ut == NULL) ppid = pid;
		else ppid = ut->pid;

		ut = NULL;

		th_child.tid = tid; 
		th_child.thread_time.seconds = thread_create_time[tid].seconds;
		th_child.thread_time.milliseconds = thread_create_time[tid].milliseconds;
		HASH_FIND(hh, unit_table, &th_child, sizeof(thread_t), ut);  /* id already in the hash? */
		if (ut == NULL) {
				ut = add_unit(tid, ppid, 0, buf);
		} else {
				ut->pid = ppid;
		}

		set_thread_group_leader(th_child, th_parent);
}

void UBSI_event(long tid, long a0, long a1, char *buf)
{
		int isNewUnit = 0;
		struct unit_table_t *ut;
		thread_t th;
		th.tid = tid; 
		th.thread_time.seconds = thread_create_time[tid].seconds;
		th.thread_time.milliseconds = thread_create_time[tid].milliseconds;
		HASH_FIND(hh, unit_table, &th, sizeof(thread_t), ut); 

		if(ut == NULL) {
				isNewUnit = 1;
				ut = add_unit(tid, tid, 0, buf);
		}

		switch(a0) {
				case UENTRY: 
//						if(ut->valid) {
								num_org_unit_entry++;
						// KYU test
								if(ut->num_syscall) {
										s.num_unit_syscall++;
										s.total_syscall += ut->num_syscall;
								} else {
										s.num_unit_no_syscall++;
								}
								if(ut->num_io_syscall > 0 || ut->num_proc_syscall > 0) {
										s.num_unit_imp_syscall++;
										s.total_imp_syscall += (ut->num_io_syscall + ut->num_proc_syscall);
								}
								if(ut->new_dep > 0) {
										s.num_unit_dep++;
										s.total_dep += ut->new_dep;
								} else {
										s.num_unit_no_dep++;
								}
//						}

						if(mergeUnit > 0) {
								ut->merge_count++;
								//if(ut->merge_count ==  1 || ut->merge_count > mergeUnit) {
								if(ut->merge_count > mergeUnit) {
										if(ut->valid) unit_end(ut, a1);
										unit_entry(ut, a1, buf);
										num_unit_entry++;
										break;
								} else if(ut->num_io_syscall > 0 || ut->num_proc_syscall > 0 || ut->new_dep > 0) {
								//KYU: test for unit integration
										num_unit_entry++;
										if(ut->valid) unit_end(ut, a1);
										unit_entry(ut, a1, buf);
										break;
								} else {
										// KYU: merge units. handle unit information. 

								}
						} else {
								if(ut->valid) unit_end(ut, a1);
								unit_entry(ut, a1, buf);
						}
						break;
				case UENTRY_ID: // this is for the new instrumentation of Firefox only (that directly emits depedant)
						unit_entry_map_uid(ut, a1, buf);
						break;
				case UEXIT: 
						if(isNewUnit == false)
						{
								unit_end(ut, a1);
								loop_exit(ut, buf);
						}
						break;
				case MREAD1:
						ut->r_addr = a1;
						ut->r_addr = ut->r_addr << 32;
						break;
				case MREAD2:
						ut->r_addr += a1;
						mem_read(ut, ut->r_addr, buf);
						break;
				case MWRITE1:
						ut->w_addr = a1;
						ut->w_addr = ut->w_addr << 32;
						break;
				case MWRITE2:
						ut->w_addr += a1;
						mem_write(ut, ut->w_addr, buf);
						break;
				case UDEP: // this is for the new instrumentation of Firefox only (that directly emits depedant)
						UBSI_dep(ut, a1, buf);
						break;
		}
}

void dup_fd(unit_table_t *unit, long fd0, long fd1)
{
		thread_group_leader_t *tgl;
		thread_group_t *tg;
		thread_hash_t *cur_t, *tmp_t;
		unit_table_t *ut;
		fd_t *t_fd0, *t_fd1;

		HASH_FIND(hh, thread_group_leader_hash, &(unit->thread), sizeof(thread_t), tgl);
		if(tgl == NULL) ut = unit;
		else {
				HASH_FIND(hh, unit_table, &(tgl->leader), sizeof(thread_t), ut);
				if(ut == NULL) ut = unit;
		}

		HASH_FIND(hh, ut->fd, &fd0, sizeof(long), t_fd0);
		if(t_fd0 == NULL) return;

		HASH_FIND(hh, ut->fd, &fd1, sizeof(long), t_fd1);
		if(t_fd1 != NULL) {
				strncpy(t_fd1->name, t_fd0->name, 1024);
				return;
		}

		t_fd1 = new fd_t();
		t_fd1->fd = fd1;
		t_fd1->inode = t_fd0->inode;
		t_fd1->type = t_fd0->type;
		t_fd1->isImportant = t_fd0->isImportant;
		strncpy(t_fd1->name, t_fd0->name, 1024);
		HASH_ADD(hh, ut->fd, fd, sizeof(long), t_fd1);
}

void set_fd(unit_table_t *unit, long fd, const char* name, long inode, fd_t::fd_type type, int isImportant)
{
		thread_group_leader_t *tgl;
		thread_group_t *tg;
		thread_hash_t *cur_t, *tmp_t;
		unit_table_t *ut;

		HASH_FIND(hh, thread_group_leader_hash, &(unit->thread), sizeof(thread_t), tgl);
		if(tgl == NULL) ut = unit;
		else {
				HASH_FIND(hh, unit_table, &(tgl->leader), sizeof(thread_t), ut);
				if(ut == NULL) ut = unit;
		}

		fd_t *new_fd;
		//HASH_FIND(hh, ut->fd, &t_fd, sizeof(fd_t), new_fd);
		HASH_FIND(hh, ut->fd, &fd, sizeof(long), new_fd);
		
		if(new_fd != NULL) 
		{
				new_fd->type = type;
				strncpy(new_fd->name, name, 1024);
				new_fd->inode = inode;
				return;
		}

		new_fd = new fd_t();
		new_fd->fd = fd;
		new_fd->type = type;
		strncpy(new_fd->name, name, 1024);
		new_fd->inode = inode;
		new_fd->isImportant = isImportant;
		HASH_ADD(hh, ut->fd, fd, sizeof(long), new_fd);

		// fd_t *t1, *t2;
		// HASH_ITER(hh, ut->fd, t1, t2) {
		// 	printf("set_fd: %ld, name: %s, inode: %ld, unit: %d_%d\n", t1->fd, t1->name, t1->inode, ut->cur_unit.tid, ut->cur_unit.loopid);
		// }
}

fd_t* get_fd(unit_table_t *unit, long fd)
{
		thread_group_leader_t *tgl;
		thread_group_t *tg;
		thread_hash_t *cur_t, *tmp_t;
		unit_table_t *ut;

		HASH_FIND(hh, thread_group_leader_hash, &(unit->thread), sizeof(thread_t), tgl);
		if(tgl == NULL) ut = unit;
		else {
				HASH_FIND(hh, unit_table, &(tgl->leader), sizeof(thread_t), ut);
				if(ut == NULL) ut = unit;
		}

		// fd_t *t1, *t2;
		// HASH_ITER(hh, ut->fd, t1, t2) {
		// 	printf("get_fd: %ld, name: %s, inode: %ld, unit: %d_%d\n", t1->fd, t1->name, t1->inode, ut->cur_unit.tid, ut->cur_unit.loopid);
		// }

		fd_t *new_fd;
		HASH_FIND(hh, ut->fd, &fd, sizeof(long), new_fd);

		
		return new_fd;
}

void clear_fd(unit_table_t *unit, long fd)
{
		thread_group_leader_t *tgl;
		thread_group_t *tg;
		thread_hash_t *cur_t, *tmp_t;
		unit_table_t *ut;

		HASH_FIND(hh, thread_group_leader_hash, &(unit->thread), sizeof(thread_t), tgl);
		if(tgl == NULL) ut = unit;
		else {
				HASH_FIND(hh, unit_table, &(tgl->leader), sizeof(thread_t), ut);
				if(ut == NULL) ut = unit;
		}
		fd_t t_fd;
		fd_t *new_fd;
		t_fd.fd = fd;
		HASH_FIND(hh, ut->fd, &fd, sizeof(long), new_fd);
		
		if(new_fd != NULL) {
				HASH_DEL(ut->fd, new_fd);
				delete new_fd;
		}
}

void analyze_syscall(unit_table_t *ut, char* buf, int sysno, bool succ, long a0)
{
		if(sysno != SYS_connect && succ == false) return;
		// printf("%s", buf);

		int i, items;
		long ret, inode;
		char *ptr, *name;
		fd_t *fd;
		string sockaddr;
		
		ut->num_syscall++;
		if(is_read(sysno) || is_write(sysno)) {
				if(a0 >= 3) {
						fd = get_fd(ut, a0);
						if(fd == NULL) {
								// fprintf(stderr, "fd is null(%d): %s\n", a0, buf);
								return;
						}
						if(fd->isImportant) ut->num_io_syscall++;
						if(CSVOUT) {
							// printf("sysno: %d, csv = true, fd->type: %s\n", sysno, fd->type);
								if(fd->type == fd_t::file) CSV_access_by_fd(ut, buf, a0, fd->name, fd->inode, "file");
								else if(fd->type == fd_t::pipe) CSV_access_by_fd(ut, buf, a0, fd->name, fd->inode, "pipe");
								else if(fd->type == fd_t::socket) CSV_socket(ut, buf, fd->name, a0);
						}
				}
				return;
		}
		
		if(sysno == SYS_recvfrom || sysno == SYS_recvmsg || sysno == SYS_recvmmsg ||
				 sysno == SYS_sendto || sysno == SYS_sendmsg || sysno == SYS_sendmmsg)
		{
				ptr = strstr(buf, "type=SOCKADDR");
				if(ptr) sockaddr = extract_string(ptr, "saddr=");
				fd = get_fd(ut, a0);
				if(fd != NULL && fd->type == fd_t::socket) {
						if(CSVOUT) CSV_socket2(ut, buf,  sockaddr.c_str(), a0, fd->name);
						if(fd->isImportant) ut->num_io_syscall++;
				} else {
						if(CSVOUT) CSV_socket2(ut, buf,  sockaddr.c_str(), a0, "");
				}
				return;
		}

		if(sysno == SYS_clone || sysno == SYS_execve || sysno == SYS_fork ||
				sysno == SYS_vfork)  {
				ut->num_proc_syscall++;
				if(CSVOUT) {
						if(sysno == SYS_execve) {
							// printf("pid from analyzer: %ld, %ld\n", ut->pid, ut->ppid);
								CSV_execve(ut, buf);
						}
						else CSV_default(ut, buf);
				}

				return;
		}
		
		if(sysno == SYS_close) {
				fd = get_fd(ut, a0);
				if(fd == NULL) {
						//fprintf(stderr, "fd is null(%d): %s\n", a0, buf);
						return;
				}
				if(CSVOUT) {
						if(fd->type == fd_t::file) CSV_access_by_fd(ut, buf, a0, fd->name, fd->inode, "file");
						else if(fd->type == fd_t::pipe) CSV_access_by_fd(ut, buf, a0, fd->name, fd->inode, "pipe");
						else if(fd->type == fd_t::socket) CSV_socket(ut, buf, fd->name, a0);
				}

				return;
		}

		if(sysno == SYS_open || sysno == SYS_openat || sysno == SYS_creat)	{
				int isImportant = 1, flag=0;
				char *temp = (char *)malloc(strlen(buf)+1);
				strcpy(temp, buf);
				string filePath = filename_open_tmp(temp, &inode, &flag);
				if (filePath.empty()){
					ignored_log ++;
					return;}
				
				const char *path = filePath.c_str();
				if(CSVOUT) CSV_file_open(ut, buf, flag);
				
				// if(eid == 35612915)
					// printf(stderr, "PATH=%s ---- %s\n", path, last_ptr);
				
				if(strstr(path, ".mozilla") != NULL) isImportant=0;
				if(strstr(path, ".cache/mozilla") != NULL) isImportant=0;
				if(strstr(path, ".Xauthority") != NULL) isImportant=0;
				if(strstr(path, "/.config/") != NULL) isImportant=0;
				if(strstr(path, "/.gconf") != NULL) isImportant=0;
				if(strstr(path, "/.dbus/") != NULL) isImportant=0;

				if(strstr(path, "/.local/share") != NULL) isImportant=0;
				if(strncmp(path, "/lib/", 5) == 0) isImportant=0;
				if(strncmp(path, "/proc/", 6) == 0) isImportant=0;
				if(strncmp(path, "/usr/", 5) == 0) isImportant=0;
				if(strncmp(path, "/etc/", 5) == 0) isImportant=0;
				if(strncmp(path, "/dev/", 5) == 0) isImportant=0;
				if(strncmp(path, "/run/", 5) == 0) isImportant=0;
				if(strncmp(path, "/var/", 5) == 0) isImportant=0;
				if(strncmp(path, "/sys/", 5) == 0) isImportant=0;
				if(strstr(path, "/firefox-54.0.1") != NULL) isImportant=0;
				if(strstr(path, "/firefox-42.0/") != NULL) isImportant=0;

	 		fprintf(testout, "path: %s\n", path); // KYU TEST

				ptr = strstr(buf, " exit=");
				if(ptr == NULL) return;
				if(sscanf(ptr, " exit=%ld", &ret) < 1) return;
				set_fd(ut, ret, path, inode, fd_t::file, isImportant);

				return;
		}
		
		if(sysno == SYS_accept || sysno == SYS_connect || sysno == SYS_accept4 || sysno == SYS_bind || sysno == SYS_listen) {
				int isImportant = 1;
				ptr = strstr(buf, "type=SOCKADDR");
				string sockaddr;
				if(ptr == NULL) {
						sockaddr.clear();
						isImportant = 0;
				} else {
						sockaddr = extract_string(ptr, "saddr=");
				}
				if(SYS_connect) {
						set_fd(ut, a0, sockaddr.c_str(), 0, fd_t::socket, isImportant);
						if(CSVOUT) CSV_socket(ut, buf, sockaddr.c_str(), a0);
				} else {
						ptr = strstr(buf, " exit=");
						if(ptr == NULL) return;
						if(sscanf(ptr, " exit=%ld", &ret) < 1) return;
						set_fd(ut, ret, sockaddr.c_str(), 0, fd_t::socket, isImportant);
						if(CSVOUT) CSV_socket(ut, buf, sockaddr.c_str(), ret);
				}

				return;
		}

		if(sysno == SYS_dup || sysno == SYS_dup2) {
				ptr = strstr(buf, " exit=");
				if(ptr == NULL) return;
				if(sscanf(ptr, " exit=%ld", &ret) < 1) return;
				dup_fd(ut, a0, ret);
				if(CSVOUT) CSV_default(ut, buf);

				return;
		}

		if(sysno == SYS_pipe || sysno == SYS_pipe2 || sysno == SYS_socketpair) {
				ptr = strstr(buf, "type=FD_PAIR");
				if(ptr == NULL) return;
				int fd0, fd1;
				if(extract_int(ptr, "fd0=", &fd0) == 0) return;
				if(extract_int(ptr, "fd1=", &fd1) == 0) return;
				set_fd(ut, fd0, "pipe", 0, fd_t::pipe, 1);
				set_fd(ut, fd1, "pipe", 0, fd_t::pipe, 1);
				if(CSVOUT) CSV_pipe(ut, buf, fd0, fd1);

				return;
		}
		
		if(!CSVOUT) return;

		if(sysno == SYS_sendfile) {
				// in_fd should be regular file, cannot be socket
				// out_fd can be either file or socket.
				int a1;
				long in_inode, out_inode;
				bool out_socket;
				fd_t *in_fd, *out_fd;
				char *in_name, *out_name;

				if(extract_hex_int(buf, " a1=", &a1) == 0) return;
				in_fd = get_fd(ut, a1);
				out_fd = get_fd(ut, a0);

				if(in_fd == NULL && out_fd == NULL) {
						//fprintf(stderr, "fd is null(%d): %s\n", a0, buf);
						return;
				}

				if(in_fd == NULL) {
						in_name = NULL;
						out_name = out_fd->name;
						if(out_fd->type == fd_t::socket) {
								out_socket = true;
						} else {
								out_socket = false;
								out_inode = out_fd->inode;
						}
				} else if(out_fd == NULL) {
						out_name = NULL;
						in_name = in_fd->name;
						in_inode = in_fd->inode;
						if(in_fd->type == fd_t::socket) in_name = NULL;
				} else {
						out_name = out_fd->name;
						in_name = in_fd->name;
						in_inode = in_fd->inode;
						if(out_fd->type == fd_t::socket) {
								out_socket = true;
						} else {
								out_socket = false;
								out_inode = out_fd->inode;
						}

						if(in_fd->type == fd_t::socket) in_name = NULL;
				}

				CSV_sendfile(ut, buf, a1, in_name, in_inode, a0, out_socket, out_name, out_inode);

				return;
		}
		
		if(sysno == SYS_link || sysno == SYS_linkat || sysno == SYS_symlink || sysno == SYS_symlinkat) {
				int oldfd = 0, newfd = 0;
				if(sysno == SYS_linkat) {
						// oldfd = a0, newfd = a2;
						oldfd = a0;
						extract_hex_int(buf, " a2=", &newfd);
				} else if(sysno == SYS_symlinkat) {
						extract_hex_int(buf, " a1=", &newfd);
				}
				CSV_link(ut, buf, sysno, oldfd, newfd);

				return;
		}

		if(sysno == SYS_unlink || sysno == SYS_unlinkat || sysno == SYS_rmdir)
		{
				CSV_unlink(ut, buf);
				return;
		}

		if(sysno == SYS_rename || sysno == SYS_renameat || sysno == SYS_renameat2)
		{
				int oldfd = 0, newfd = 0;
				if(sysno == SYS_renameat || sysno == SYS_renameat2) {
						// oldfd = a0, newfd = a2;
						oldfd = a0;
						extract_hex_int(buf, " a2=", &newfd);
				}
				CSV_rename(ut, buf, sysno, oldfd, newfd);

				return;
		}

		if((extract_int(buf, "items=", &items) == 0) || items == 0) {
				// TODO: if arg is filedescriptor, handle that
				if(sysno == SYS_ioctl || sysno == SYS_fcntl) {
						if(a0 >= 3) {
								fd = get_fd(ut, a0);
								if(fd == NULL) {
										//fprintf(stderr, "fd is null(%d): %s\n", a0, buf);
										return;
								}
								if(fd->type == fd_t::file) CSV_access_by_fd(ut, buf, a0, fd->name, fd->inode, "file");
								else if(fd->type == fd_t::pipe) CSV_access_by_fd(ut, buf, a0, fd->name, fd->inode, "pipe");
								else if(fd->type == fd_t::socket) CSV_socket(ut, buf, fd->name, a0);
						}
				} else {
						CSV_default(ut, buf);
				}
				return;
		} else {
				//items > 0
				if(strstr(buf, "type=PATH")) CSV_file_access_by_name(ut, buf, sysno);
				if(ptr = strstr(buf, "type=SOCKADDR")) {
						sockaddr = extract_string(ptr, "saddr=");
						CSV_socket(ut, buf, sockaddr.c_str(), a0);
				}
				return;
		}
}

void non_UBSI_event(long tid, int sysno, bool succ, long a0, long a1, long a2, char *buf)
{
		char *ptr;
		int time, retno;
		long ret;

		struct unit_table_t *ut;

		thread_t th;
		th.tid = tid;
		th.thread_time.seconds = thread_create_time[tid].seconds;
		th.thread_time.milliseconds = thread_create_time[tid].milliseconds;
		HASH_FIND(hh, unit_table, &th, sizeof(thread_t), ut); 

		if(ut == NULL) {
				ut = add_unit(tid, tid, 0, buf);
		}
		
		if(succ == true && (sysno == SYS_clone || sysno == SYS_fork || sysno == SYS_vfork))
		{
				ptr = strstr(buf, " exit=");
				if(ptr == NULL) return;

				retno = sscanf(ptr, " exit=%ld", &ret);
				if(retno != 1) return;

				unit_table_t *child_ut;
				thread_t child_th;
				child_th.tid = ret;
				child_th.thread_time.seconds = thread_create_time[ret].seconds;
				child_th.thread_time.milliseconds = thread_create_time[ret].milliseconds;
				HASH_FIND(hh, unit_table, &child_th, sizeof(thread_t), child_ut); 
				
				if(child_ut != NULL) proc_end(child_ut);

				set_thread_time(buf, &thread_create_time[ret]); /* set thread_create_time */
				if(sysno == SYS_clone && a2 > 0) { // thread_creat event
						set_pid(ret, tid, buf);
				}
		} else if(succ == true && ( sysno == SYS_execve || sysno == 322 || sysno == SYS_exit || sysno == SYS_exit_group)) {
				// execve, exit or exit_group

				if(sysno == SYS_exit_group) {
						proc_group_end(ut);
				} else if(sysno == SYS_exit) {
						proc_end(ut);
				} else {
						if(sysno == SYS_execve){ // execve
								string comm = extract_string(buf, " comm=");
								string exe = extract_string(buf, " exe=");
								comm.copy(ut->comm, 1024);
								exe.copy(ut->exe, 1024);
								set_thread_time(buf, &thread_create_time[tid]);
								// printf("59: pid after value set: %ld\n", ut->pid);
								// updated start time to the time when execve happened. Done to reflect what happens in Audit reporter.
						}
						// proc_end(ut);
				}
				if(sysno == SYS_exit_group || sysno == SYS_exit){ // exit_group or exit
						// Need to set time to zero because it means that time hasn't been set for this process.
						// The zero condition is used to set seen time for process otherwise it would be updated each time.
						thread_create_time[tid].seconds = thread_create_time[tid].milliseconds = 0;
				}
		} else if(succ == true && sysno == SYS_kill) {

				// clear target process' memory if kill syscall with SIGINT or SIGKILL or SIGTERM
				// It might cause false negative if the taget process has custom signal hander for SIGTERM or SIGINT
				if(a1 == SIGINT || a1 == SIGKILL || a1 == SIGTERM) { 
						unit_table_t *target_ut;
						thread_t target_thread;
						target_thread.tid = a0;
						target_thread.thread_time.seconds = thread_create_time[a0].seconds;
						target_thread.thread_time.milliseconds = thread_create_time[a0].milliseconds;

						HASH_FIND(hh, unit_table, &target_thread, sizeof(thread_t), target_ut);
						if(target_ut == NULL) return;
						if(a1 < MAX_SIGNO) {
								if(target_ut->signal_handler[a1] == true) return; // If the target process has signal handler, ignore the signal.
						}

						thread_group_leader_t *target_tgl;
						HASH_FIND(hh, thread_group_leader_hash, &(target_thread), sizeof(thread_t), target_tgl);
						if(target_tgl == NULL) proc_end(target_ut);
						else proc_group_end(target_ut);
				}
		} else if(succ == true && sysno == SYS_rt_sigaction) {  //If the thread has signal handlers, signals will not kill it.
				if(a0 < MAX_SIGNO) {
						ut->signal_handler[a0] = true;
				}
		}

		if(CSVOUT || mergeUnit > 0) analyze_syscall(ut, buf, sysno, succ, a0);
		if(!CSVOUT) emit_log(ut, buf, false, false);
}

bool get_succ(char *buf, int sysno)
{
		char *ptr;
		char succ[16];
		int i=0;

// Syscall exit(60) and exit_group(231) do not return, thus do not have "success" field. They always succeed.
		if(sysno == 60 || sysno == 231) return true; 

		ptr = strstr(buf, " success=");
		if(ptr == NULL) {
				incomplete_record = true;
				return false;
		}
		ptr+=9;

		for(i=0; ptr[i] != ' '; i++)
		{
				succ[i] = ptr[i];
		}
		succ[i] = '\0';
		if(strncmp(succ, "yes", 3) == 0) {
				return true;
		}
		return false;
}

void ubsi_intercepted_handler(char* buf) {

		char* tmp;
		char* ptr_start;
		char* ptr_end;
		int tmp_current_index = 0;
		int buf_len;

		ptr_start = buf;

		if(ptr_start != NULL){
				buf_len = strlen(buf) + 1; // null char
				tmp = (char*) 	malloc(sizeof(char)*buf_len);
				if(tmp != NULL){
					memset(tmp, 0, buf_len);
					
					ptr_end = strstr(buf, "ubsi_intercepted=");

					if(ptr_end != NULL){			
							tmp_current_index = (ptr_end - ptr_start);
							strncpy(&tmp[0], buf, tmp_current_index);

							ptr_start = strstr(buf, "syscall=");

							if(ptr_start != NULL){
									strncpy(&tmp[tmp_current_index], ptr_start, (&buf[strlen(buf)] - ptr_start - 2));

									tmp[strlen(tmp)] = '\n';

									syscall_handler(tmp);
							}else{
								incomplete_record = true;
									fprintf(stderr, "ERROR: Malformed UBSI record: 'syscall' not found\n");	
							}
					}else{
						 incomplete_record = true;
							fprintf(stderr, "ERROR: Malformed UBSI record: 'ubsi_intercepted' not found\n");
					}
					if(tmp) free(tmp);
				}else{
				 incomplete_record = true;
					fprintf(stderr, "ERROR: Failed to allocate memory for 'ubsi_intercepted' record\n");	
				}
		}else{
				incomplete_record = true;
				fprintf(stderr, "ERROR: NULL buffer in UBSI record handler\n");	
		}
}

void netio_handler(char *buf)
{
		char *ptr;
		int sysno, retno;
		long fd, tid, ppid;
		int succ = 0;
		struct unit_table_t *ut;
		string local_addr, remote_addr;
		char *l_addr, *r_addr, *fd_name;
		fd_t *t_fd;

		incomplete_record = false;
		
		if(extract_int(buf, "syscall=", &sysno) == 0) return;

		ptr = strstr(buf, " pid=");
		retno = sscanf(ptr, " pid=%ld ppid=%ld", &tid, &ppid);
		
		if(retno != 2) return;

		if(extract_int(buf, " success=", &succ) == 0) return;
		if(succ == 0) return;

		set_thread_seen_time_conditionally(tid, buf);

		thread_t th;  
		th.tid = tid; 
		th.thread_time.seconds = thread_create_time[tid].seconds;
		th.thread_time.milliseconds = thread_create_time[tid].milliseconds;
		HASH_FIND(hh, unit_table, &th, sizeof(thread_t), ut); 

		if(ut == NULL) {
				ut = add_unit(tid, tid, 0, buf);
		}
		
		if(extract_long(buf, " fd=", &fd) == 0) fd = -1;
		local_addr = extract_string(buf, " local_saddr=");
		remote_addr = extract_string(buf, " remote_saddr=");
		
		/*if(!local_addr.empty()) l_addr = local_addr.c_str();
		else l_addr = NULL;
		if(!remote_addr.empty()) r_addr = remote_addr.c_str();
		else r_addr = NULL;
*/
		t_fd = get_fd(ut, fd);
		if(t_fd && t_fd->type == fd_t::socket)
		{
				fd_name = t_fd->name;
				if(t_fd->isImportant) ut->num_io_syscall++;
		} else
				fd_name = NULL;

		if(CSVOUT) {
				if(local_addr.empty() && remote_addr.empty()) 
						CSV_netio(ut, buf, fd, fd_name, NULL, NULL);
				else if(local_addr.empty()) 
						CSV_netio(ut, buf, fd, fd_name, NULL, remote_addr.c_str());
				else if(remote_addr.empty())
						CSV_netio(ut, buf, fd, fd_name, local_addr.c_str(), NULL);
				else
						CSV_netio(ut, buf, fd, fd_name, local_addr.c_str(), remote_addr.c_str());
		} else emit_log(ut, buf, false, false);
}

void syscall_handler(char *buf)
{
		char *ptr;
		int sysno, retno;
		long a0, a1, a2, a3, pid, ppid;
		bool succ = false;

		incomplete_record = false;

		ptr = strstr(buf, " syscall=");
		if(ptr == NULL) return;

		retno = sscanf(ptr, " syscall=%d", &sysno);
		if(retno != 1) return;

		ptr = strstr(buf, " a0=");
		if(ptr == NULL) return;

		retno = sscanf(ptr, " a0=%lx a1=%lx a2=%lx a3=%lx", &a0, &a1, &a2, &a3);
		if(retno != 4) return;

		ptr = strstr(ptr, " ppid=");
		retno = sscanf(ptr, " ppid=%ld pid=%ld", &ppid, &pid);
		
		if(retno != 2) return;

		succ = get_succ(buf, sysno);
		
		// Set seen time here if not already set. thread_create_time is used in the functions below.
		set_thread_seen_time_conditionally(pid, buf);

		if(sysno == 62)
		{
				if(a0 == UENTRY || a0 == UEXIT || a0 == MREAD1 || a0 == MREAD2 || a0 == MWRITE1 || a0 ==MWRITE2 || a0 == UDEP || a0 == UENTRY_ID)
				{
						UBSI_event(pid, a0, a1, buf);
				} else {
						non_UBSI_event(pid, sysno, succ, a0, a1, a2, buf);
				}
		} else {
				non_UBSI_event(pid, sysno, succ, a0, a1, a2, buf);
		}
}

#define EVENT_LENGTH 1048576
#define REORDERING_WINDOW 10000
int next_event_id = 0;

int UBSI_buffer_flush()
{
		struct event_buf_t *eb;
		fprintf(stderr, "UBSI flush the log buffer: %d events\n", HASH_COUNT(event_buf));

		while(HASH_COUNT(event_buf) > 0)
		{
				//HASH_FIND_INT(event_buf, &next_event_id, eb);
				HASH_FIND(hh, event_buf, &next_event_id, sizeof(int), eb);
				next_event_id++;
				if(eb != NULL) {
						if(strstr(eb->event, "ubsi_intercepted=") != NULL){
								if(UBSIAnalysis) ubsi_intercepted_handler(eb->event);
								else printf("%s", eb->event);
						} else if(strstr(eb->event, "netio_intercepted=") != NULL) {
								if(UBSIAnalysis) netio_handler(eb->event);
								else printf("%s", eb->event);
						} else if(strstr(eb->event, "type=SYSCALL") != NULL) {
								if(UBSIAnalysis) syscall_handler(eb->event);
								else printf("%s", eb->event);
						} else {
								if(!CSVOUT) printf("%s", eb->event);
						}
						HASH_DEL(event_buf, eb);
						if(eb && eb->event) free(eb->event);
						if(eb) delete eb;
				} 
		}
}

void UBSI_buffer_emit()
{
		struct event_buf_t *eb;

		while(HASH_COUNT(event_buf) > REORDERING_WINDOW)
		{
				HASH_FIND(hh, event_buf, &next_event_id, sizeof(int), eb);
				next_event_id++;
				if(eb != NULL) {
						if((eb->items > eb->items_read) && eb->waiting < REORDERING_WINDOW) {
								eb->waiting++;
								return;
						}
						if(eb->waiting >= REORDERING_WINDOW) {
								fprintf(stderr, "waiting items expires! eb->items %d, eb->items_read %d, eb->waiting %d, buf: %s\n", eb->items, eb->items_read, eb->waiting, eb->event);
						}

						if(strstr(eb->event, "ubsi_intercepted=") != NULL){
								if(UBSIAnalysis) ubsi_intercepted_handler(eb->event);
								else printf("%s", eb->event);
						} else if(strstr(eb->event, "netio_intercepted=") != NULL) {
								if(UBSIAnalysis) netio_handler(eb->event);
								else printf("%s", eb->event);
						} else if(strstr(eb->event, "type=SYSCALL") != NULL) {
								if(UBSIAnalysis) syscall_handler(eb->event);
								else printf("%s", eb->event);
						} else {
								if(!CSVOUT) printf("%s", eb->event);
						}
						HASH_DEL(event_buf, eb);
						if(eb && eb->event) free(eb->event);
						if(eb) delete eb;
				} 
		}
}

int UBSI_buffer(char *buf)
{
		int cursor = 0;
		int event_start = 0;
		long id = 0;
		char event[EVENT_LENGTH];
		int event_byte = 0;
		char *ptr;
		static char remain[BUFFER_LENGTH];
		static int remain_byte = 0;

		struct event_buf_t *eb = NULL;

		for(cursor=0; cursor < strlen(buf); cursor++) {
				if(buf[cursor] == '\n') {
						if(event_start == 0 && remain_byte > 0) {
								strncpy(event, remain, remain_byte-1);
								strncpy(event+remain_byte-1, buf, cursor+1);
								event[remain_byte + cursor] = '\0';
								event_byte = remain_byte + cursor;
								remain_byte = 0;
						} else {
								strncpy(event, buf+event_start, cursor-event_start+1);
								event[cursor-event_start+1] = '\0';
								event_byte = cursor-event_start+1;
						}
						
						if(strstr(event, "type=DAEMON_START") != NULL) {
								// flush events in reordering buffer.
								UBSI_buffer_flush();
						}

						if(strstr(event, "type=EOE") == NULL && strstr(event, "type=UNKNOWN[") == NULL && strstr(event, "type=PROCTILE") == NULL) {
								ptr = strstr(event, ":");
								if(ptr == NULL) {
										id = -1; // to indicate error. it is set back to zero once it gets out of the if condition.
										printf("ERROR: cannot parse event id, buf = %s\n", buf);
								} else {
										id = strtol(ptr+1, NULL, 10);
										if(next_event_id == 0) next_event_id = id;
								}
								if(id != -1){
									HASH_FIND(hh, event_buf, &id, sizeof(int), eb);
									if(eb == NULL) {
										 while(HASH_COUNT(event_buf) > REORDERING_WINDOW)
														UBSI_buffer_emit();

											eb = new event_buf_t();
										 assert(eb);
											eb->id = id;
											eb->items = 0;
											eb->items_read=0;
											eb->waiting = 0;

											if(strstr(event, "syscall=") != NULL) {
													if(extract_int(event, "items=", &(eb->items)) == 0)
															eb->items = 0;
											} else {
													if(strstr(event, "type=PATH") != NULL) {
														 fprintf(stderr, "PATH appears first[%d]: %s\n", id, event);
													}
										 }

											eb->event = (char*) malloc(sizeof(char) * (event_byte+1));
										 assert(eb->event);
											eb->event_byte = event_byte;
											strncpy(eb->event, event, event_byte+1);
											//HASH_ADD_INT(event_buf, id, eb);
											HASH_ADD(hh, event_buf, id, sizeof(int), eb);
											if(next_event_id > id) {
													next_event_id = id;
											}
									} else {
											eb->event = (char*) realloc(eb->event, sizeof(char) * (eb->event_byte+event_byte+1));
											strncpy(eb->event+eb->event_byte, event, event_byte+1);
											eb->event_byte += event_byte;
											if(strstr(event, "item=") != NULL) eb->items_read++;
											if(strstr(event, "syscall=") != NULL) {
													if(extract_int(event, "items=", &(eb->items)) == 0)
															eb->items=0;
											}
											if(next_event_id > id) {
													next_event_id = id;
											}
									}
								}
						}
						event_start = cursor+1;
						id = 0;
				}
		}
		if(buf[strlen(buf)-1] != '\n') {
				remain_byte = cursor - event_start+1;
				strncpy(remain, buf+event_start, remain_byte);
				remain[remain_byte] = '\0';
		} else {
				remain_byte = 0;
		}
}

void UBSI_sig_handler(int signo)
{
		if(waitForEnd == FALSE) {
				UBSI_buffer_flush();
				exit(0);
		} else {
				// ignore the signal and the process continues until the end of the input stream/file.
		}
}

int get_max_pid()
{
		int max_pid;
	 FILE *fp = fopen("/proc/sys/kernel/pid_max", "r");
		fscanf(fp, "%d", &max_pid);
		fclose(fp);

		return max_pid;
}

void kyu_test_helper(long num, long total, const char *str)
{
		if(total == 0) total=1;
		fprintf(stderr, "%s: %ld (%.2f%%)\n", str, num, (float)((float)(num*100)/(float)total));
}

void kyu_test(int max_pid)
//KYU: test
{
		int i;
		int num_threads = 0;
		int total_unit = s.num_unit_syscall + s.num_unit_no_syscall;
		kyu_test_helper(s.num_unit_no_syscall, total_unit, "num_unit_no_syscall");
		kyu_test_helper(s.num_unit_syscall, total_unit, "num_unit_syscall");
		kyu_test_helper(s.num_unit_imp_syscall, total_unit, "num_unit_imp_syscall");
		kyu_test_helper(s.num_unit_no_dep, total_unit, "num_unit_no_dep");
		kyu_test_helper(s.num_unit_dep, total_unit, "num_unit_dep");
		
		if(s.num_unit_syscall == 0) s.num_unit_syscall = 1;
		fprintf(stderr, "avg.syscall %ld\n", s.total_syscall/s.num_unit_syscall);
		if(s.num_unit_imp_syscall == 0) s.num_unit_imp_syscall = 1;
		fprintf(stderr, "avg.imp.syscall %ld\n", s.total_imp_syscall/s.num_unit_imp_syscall);
		if(s.num_unit_dep == 0) s.num_unit_dep = 1;
		fprintf(stderr, "avg.dep %ld\n", s.total_dep / s.num_unit_dep);

		if(num_org_unit_entry == 0) num_org_unit_entry = 1;
		fprintf(stderr, "\nafter integration: %d / %d(%.2f%%)\n", num_unit_entry, num_org_unit_entry, (float)((float)(num_unit_entry*100)/(float)num_org_unit_entry));

		for(i = 0; i < max_pid; i++) {
				if(thread_create_time[i].seconds > 0) num_threads++;
		}

		fprintf(stderr, "thread: %d\n", num_threads);
		fprintf(stderr, "Ignored logs: %ld\n", ignored_log);
}

