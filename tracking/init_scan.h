#ifndef UBSI_INIT_SCAN
#define UBSI_INIT_SCAN

int init_scan(const char *name);
int save_init_tables(const char *name);
int load_init_tables(const char *name);
int get_sysno(char *syscall);

extern long num_syscall;
extern double backtrack_ts;
extern double forward_ts;

#endif
