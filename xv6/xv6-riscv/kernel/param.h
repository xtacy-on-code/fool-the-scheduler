// mlfq
#define NLEVEL        3        // slices 1,2,4 ticks
#define TICK_INTERVAL 100000   // 10 ms at 10 MHz
#define SF_MLFQ    1
#define SF_ACCT    2  // allotment
#define SF_PRECISE 4  // charge real time not ticks
#define SF_FAIR    8  // least cpu first in a queue
#define NPROC       64                // maximum number of processes
#define NCPU        8                 // maximum number of CPUs
#define NOFILE      16                // open files per process
#define NFILE       100               // open files per system
#define NINODE      50                // maximum number of active i-nodes
#define NDEV        10                // maximum major device number
#define ROOTDEV     1                 // device number of file system root disk
#define MAXARG      32                // max exec arguments
#define MAXOPBLOCKS 10                // max # of blocks any FS op writes
#define LOGBLOCKS   (MAXOPBLOCKS * 3) // max data blocks in on-disk log
#define NBUF        (MAXOPBLOCKS * 3) // size of disk block cache
#define FSSIZE      2000              // size of file system in blocks
#define MAXPATH     128               // maximum file path name
#define USERSTACK   1                 // user stack pages
