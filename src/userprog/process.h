#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>
#include "filesys/file.h"

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127
#define MAX_ARGS 64
#define MAX_FD 128

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;     /* Page directory. */
  char process_name[16]; /* Name of the main thread */
  pid_t pid;
  struct thread* main_thread; /* Pointer to main thread */

  /* Process Operations */
  struct list children;             /* List of child processes */
  struct process_info* parent_info; /* Shared Data*/
  struct process* parent;           /* Pointer to parent process */

  /* File Operations*/
  struct list fd_list;
  uint32_t next_fd;

  /* Main thread join semaphore*/
  struct semaphore main_thread_join;

  /* Thread and User Operations */
  struct list user_threads;    // List of non-main threads created in this process
  bool exit_status;            // whether an exit() process control syscall has been called
  struct list user_locks;      // List for user to create locks with lock_init as needed
  struct list user_semaphores; // List of semaphores for users

  struct list join_statuses;
};

struct thread_wrap {
  stub_fun sf;
  pthread_fun tf;
  void* thread_args;
  struct process* pcb;
  struct semaphore sema;
};

struct process_info {
  pid_t pid; /* process identifier*/
  pid_t parent_pid;
  int exit_code; /* exit code*/
  struct semaphore sema;
  struct list_elem elem; /*list element*/
  int ref_count;
  struct lock ref_lock;
  bool load_success;
  struct semaphore child_load_sema; /* If the child successfully loaded or not*/
  bool has_waiter;
};

struct file_entry* find_file_by_fd(struct list* file_list, int fd);

struct process_args {
  /* Owned by process.c. */
  char* file_name;
  char** argv;
  int argc;

  struct process_info* shared_data;
};

void userprog_init(void);

pid_t process_execute(const char* task);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void*);
void pthread_exit_main(void);

#endif /* userprog/process.h */
