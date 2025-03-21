#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "threads/synch.h"

#include "devices/shutdown.h"
#include "devices/input.h"
static struct lock global_lock;
static void syscall_handler(struct intr_frame*);
void validate_pointer(uint32_t* eax_reg, void* stack_pointer, size_t len);
bool validate_string(uint32_t* eax_reg, const char* str);
void exit(uint32_t* eax_reg, int exit_code);
void syscall_init(void) {
  lock_init(&global_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  // Validate the pointer to ensure it is in user memory
  // 4 byte mmeory region for the first args
#define file_descriptor (int)args[1]
#define pos (off_t) args[2]
#define buffer (void*)args[2]
#define size (size_t) args[3]

  validate_pointer(&f->eax, args, sizeof(uint32_t));

  struct file_entry* file;

  struct thread* t = thread_current();

  switch (args[0]) {
    case SYS_PT_CREATE:
      validate_pointer(&f->eax, args + 1, sizeof(stub_fun));
      validate_pointer(&f->eax, args + 2, sizeof(pthread_fun));
      validate_pointer(&f->eax, args + 3, sizeof(void*));
      tid_t tid = pthread_execute(args[1], args[2], args[3]);
      if (tid == TID_ERROR) {
        f->eax = -1;
      } else {
        f->eax = tid;
      }
      break;
    case SYS_PT_EXIT:
      if (t == t->pcb->main_thread) {
        pthread_exit_main();
      } else {
        pthread_exit(f->esp);
      }
      break;
    case SYS_PT_JOIN:
      validate_pointer(&f->eax, args + 1, sizeof(tid_t));
      tid_t th = pthread_join(args[1]);
      if (th == TID_ERROR) {
        f->eax = -1;
      } else {
        f->eax = th;
      }
      break;
    case SYS_GET_TID:
      f->eax = t->tid;
      break;
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_WAIT:
      f->eax = process_wait(args[1]);
      break;
    case SYS_PRACTICE:
    case SYS_EXIT:
    case SYS_COMPUTE_E:
    case SYS_EXEC:
      validate_pointer(&f->eax, args + 1, sizeof(uint32_t));
      if (args[0] == SYS_PRACTICE)
        f->eax = args[1] + 1;
      else if (args[0] == SYS_EXIT) {
        exit(&f->eax, args[1]);
      } else if (args[0] == SYS_COMPUTE_E) {
        f->eax = sys_sum_to_e(args[1]);
      } else {
        validate_string(&f->eax, args[1]);
        pid_t pid = process_execute((const char*)args[1]);
        if (pid == TID_ERROR)
          f->eax = -1;
        else {
          f->eax = pid;
        }
      }
      break;
    case SYS_CREATE:
    case SYS_REMOVE:
    case SYS_OPEN:
      if (!validate_string(&f->eax, args[1])) {
        f->eax = (args[0] == SYS_CREATE || args[0] == SYS_REMOVE) ? false : -1;
        break;
      }
      const char* file_name = (const char*)args[1];
      validate_pointer(&f->eax, args + 2, sizeof(unsigned));
      unsigned initial_size = (unsigned)args[2];
      if (args[0] == SYS_CREATE) {
        lock_acquire(&global_lock);
        f->eax = filesys_create(file_name, initial_size);
        lock_release(&global_lock);
      } else if (args[0] == SYS_REMOVE) {
        lock_acquire(&global_lock);
        f->eax = filesys_remove(args[1]);
        lock_release(&global_lock);
      } else {
        if (file_descriptor < 2) {
          f->eax = -1;
        } else {
          file = malloc(sizeof(struct file_entry));
          lock_acquire(&global_lock);
          file->file = filesys_open(file_name);
          lock_release(&global_lock);
          if (file != NULL && file->file != NULL) {
            list_push_back(&t->pcb->fd_list, &file->list_elem);
            file->fd = (t->pcb->next_fd)++;
            f->eax = file->fd;
          } else
            f->eax = -1;
        }
      }
      break;
    case SYS_WRITE:
    case SYS_READ:
    case SYS_FILESIZE:
      validate_pointer(&f->eax, args + 1, sizeof(int));
      file = find_file_by_fd(&t->pcb->fd_list, file_descriptor);
      if (file != NULL || (file_descriptor == STDIN_FILENO && args[0] == SYS_READ) ||
          (file_descriptor == STDOUT_FILENO && args[0] == SYS_WRITE)) {
        if (args[0] == SYS_FILESIZE) {
          lock_acquire(&global_lock);
          f->eax = file_length(file->file);
          lock_release(&global_lock);
        } else if (args[0] == SYS_READ) {
          if (file_descriptor == STDIN_FILENO) {
            lock_acquire(&global_lock);
            f->eax = input_getc();
            lock_release(&global_lock);
          } else {
            validate_pointer(&f->eax, args[2], sizeof(int));
            lock_acquire(&global_lock);
            f->eax = file_read(file->file, buffer, size);
            lock_release(&global_lock);
          }
        } else {
          if (file_descriptor == STDOUT_FILENO) {
            lock_acquire(&global_lock);
            putbuf(buffer, size);
            lock_release(&global_lock);
            f->eax = size;
          } else {
            validate_pointer(&f->eax, args[2], sizeof(int));
            lock_acquire(&global_lock);
            f->eax = file_write(file->file, buffer, size);
            lock_release(&global_lock);
          }
        }
      } else {
        f->eax = -1;
      }
      break;
    case SYS_SEEK:
      file = find_file_by_fd(&t->pcb->fd_list, file_descriptor);

      if (file != NULL) {
        lock_acquire(&global_lock);
        file_seek(file->file, pos);
        lock_release(&global_lock);
      }
      break;
    case SYS_TELL:
      file = find_file_by_fd(&t->pcb->fd_list, file_descriptor);

      if (file) {
        lock_acquire(&global_lock);
        f->eax = file_tell(file->file);
        lock_release(&global_lock);
      } else {
        f->eax = -1;
      }
      break;
    case SYS_CLOSE:
      file = find_file_by_fd(&t->pcb->fd_list, file_descriptor);
      if (file != NULL) {
        lock_acquire(&global_lock);
        file_close(file->file);
        lock_release(&global_lock);
        list_remove(&file->list_elem);
        free(file);
      }
      break;

    case SYS_LOCK_INIT:
    case SYS_LOCK_ACQUIRE:
    case SYS_LOCK_RELEASE:
    case SYS_SEMA_INIT:
    case SYS_SEMA_DOWN:
    case SYS_SEMA_UP:
      validate_pointer(&f->eax, args + 1, sizeof(struct lock*));
      if (args[1] == NULL) {
        f->eax = 0;
        break;
      }

      //get the pcb
      struct process* p = thread_current()->pcb;
      void* user_synch = (void*)args[1];

      if (args[0] == SYS_LOCK_INIT) {
        struct list_elem* e;
        for (e = list_begin(&(p->user_locks)); e != list_end(&(p->user_locks)); e = list_next(e)) {
          struct lock* existing_lock = list_entry(e, struct lock, user_elem);
          if (existing_lock->user_lock == user_synch) {
            f->eax = 1;
            break;
          }
        }
        if (e == list_end(&(p->user_locks))) {
          struct lock* kernel_lock = malloc(sizeof(struct lock));
          if (kernel_lock == NULL) {
            f->eax = 0;
            break;
          }
          lock_init(kernel_lock);
          kernel_lock->user_lock = user_synch;
          list_push_back(&(p->user_locks), &(kernel_lock->user_elem));
          f->eax = 1;
        }
        break;

      } else if (args[0] == SYS_LOCK_ACQUIRE) {
        bool found = false;
        struct list_elem* e;
        for (e = list_begin(&(p->user_locks)); e != list_end(&(p->user_locks)); e = list_next(e)) {
          struct lock* curr_lock = list_entry(e, struct lock, user_elem);
          if (curr_lock->user_lock == user_synch) {
            found = true;
            if (lock_held_by_current_thread(curr_lock)) {
              f->eax = 0;
            } else {
              lock_acquire(curr_lock);
              f->eax = 1;
            }
            break;
          }
        }
        if (!found)
          f->eax = 0;

        break;
      } else if (args[0] == SYS_LOCK_RELEASE) {
        bool found = false;
        struct list_elem* e;
        for (e = list_begin(&(p->user_locks)); e != list_end(&(p->user_locks)); e = list_next(e)) {
          struct lock* curr_lock = list_entry(e, struct lock, user_elem);
          if (curr_lock->user_lock == user_synch) {
            found = true;
            if (lock_held_by_current_thread(curr_lock)) {
              lock_release(curr_lock);
              f->eax = 1;
            } else {
              f->eax = 0;
            }
            break;
          }
        }
        if (!found)
          f->eax = 0;

        break;
      }
      if (args[0] == SYS_SEMA_INIT) {
        //check to see if value is negative
        if ((int)args[2] < 0) {
          f->eax = 0;
          break;
        }

        //allocate space for kernel semaphore
        struct semaphore* kernel_sema = malloc(sizeof(struct semaphore));
        if (kernel_sema == NULL) {
          f->eax = 0;
          break;
        }

        //initialize the semaphore
        sema_init(kernel_sema, args[2]);
        kernel_sema->user_sema = user_synch;

        //check if semaphore is in list, if not add it to the user_sema list
        bool in_list = false;
        struct list_elem* e;
        for (e = list_begin(&(p->user_semaphores)); e != list_end(&(p->user_semaphores));
             e = list_next(e)) {
          struct semaphore* existing_sema = list_entry(e, struct semaphore, user_elem);
          if (existing_sema == kernel_sema) {
            in_list = true;
          }
        }

        if (!in_list) {
          list_push_back(&(p->user_semaphores), &(kernel_sema->user_elem));
        }

        f->eax = 1;
        break;

      } else if (args[0] == SYS_SEMA_DOWN) {
        struct list_elem* e;
        bool found = false;
        for (e = list_begin(&(p->user_semaphores)); e != list_end(&(p->user_semaphores));
             e = list_next(e)) {
          struct semaphore* curr_sema = list_entry(e, struct semaphore, user_elem);
          if (curr_sema->user_sema == user_synch) {
            sema_down(curr_sema);
            f->eax = 1;
            found = true;
            break;
          }
        }

        if (!found) {
          f->eax = 0;
        }

        break;
      } else {
        struct list_elem* e;
        for (e = list_begin(&(p->user_semaphores)); e != list_end(&(p->user_semaphores));
             e = list_next(e)) {
          struct semaphore* curr_sema = list_entry(e, struct semaphore, user_elem);
          if (curr_sema->user_sema == user_synch) {
            sema_up(curr_sema);
            f->eax = 1;
            break;
          }
        }
        break;
      }
  }

#undef file_descriptor
#undef pos
#undef buffer
#undef size
}

/*
  invalid memory access including null pointers, 
  invalid pointers (e.g. pointing to unmapped memory), 
  and illegal pointers (e.g. pointing to kernel memory).
  */
void validate_pointer(uint32_t* eax_reg, void* stack_pointer, size_t len) {
  if (!is_user_vaddr(stack_pointer + len) ||
      pagedir_get_page(thread_current()->pcb->pagedir, stack_pointer + len) == NULL) {
    exit(eax_reg, -1);
  }
}

bool validate_string(uint32_t* eax_reg, const char* str) {
  // Iterate through each byte in the string
  for (const char* ptr = str;; ptr++) {
    // Ensure the pointer is a valid user address
    validate_pointer(eax_reg, ptr, sizeof(char));

    // Stop when we find the null terminator, which marks the end of the string
    if (*ptr == '\0') {
      if (str - ptr == 0) //Empty Strings
        return false;
      break;
    }
  }

  return true;
}

void exit(uint32_t* eax_reg, int exit_code) {
  *eax_reg = exit_code;
  thread_current()->exit_code = exit_code;
  thread_current()->pcb->exit_status = true;
  /* we are setting the thread exit code, not the shared data structure, but when i edit it, it gives kernel fault, why?*/
  process_exit();
}