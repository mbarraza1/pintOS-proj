#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp, struct process_args* args);
bool setup_thread(void (**eip)(void), void** esp, void* arg);

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;
  list_init(&t->pcb->children);

  /* Kill the kernel if we did not succeed */
  ASSERT(success);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* task) {
  char* fn_copy;
  char* task_cpy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */

  task_cpy = malloc(sizeof(char) * (strlen(task) + 1));

  if (task_cpy == NULL)
    return TID_ERROR;

  //Parse task
  strlcpy(task_cpy, task, PGSIZE);

  char* save_ptr;
  int argc = 0;

  struct process_args* args = malloc(sizeof(struct process_args));
  if (args == NULL) {
    free(task_cpy);
    return TID_ERROR;
  }
  args->argv = malloc(sizeof(char*) * MAX_ARGS);

  char* token = strtok_r(task_cpy, " ", &save_ptr);
  while (token != NULL && argc < MAX_ARGS) {
    args->argv[argc++] = token;
    token = strtok_r(NULL, " ", &save_ptr);
  }
  args->argv[argc] = NULL;
  fn_copy = palloc_get_page(0);
  strlcpy(fn_copy, task_cpy, PGSIZE);

  args->file_name = fn_copy;
  args->argc = argc;

  /* Create child process */

  struct process_info* child = malloc(sizeof(struct process_info));
  if (child == NULL) {
    free(args->argv);
    palloc_free_page(fn_copy);
    free(task_cpy);
    return TID_ERROR;
  }
  child->exit_code = -1;
  child->load_success = false;
  child->has_waiter = false;
  child->parent_pid = thread_current()->tid;
  sema_init(&child->sema, 0);
  lock_init(&child->ref_lock);
  child->ref_count = 2;
  args->shared_data = child;

  list_push_back(&thread_current()->pcb->children, &child->elem);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(fn_copy, PRI_DEFAULT, start_process, args);
  child->pid = tid;
  if (tid == TID_ERROR) {
    palloc_free_page(fn_copy);
    free(task_cpy);
    return TID_ERROR;
  }

  /* Down in the parent process after creating the child process and decremeent count if we couldn't run*/
  sema_down(&child->sema); //Loading
  if (!child->load_success) {
    lock_acquire(&child->ref_lock);
    int ref_count = --child->ref_count;
    lock_release(&child->ref_lock);
    if (ref_count == 0) {
      list_remove(&child->elem);
      free(child);
    }
    //start_process will free fn_copy
    free(task_cpy);
    return TID_ERROR;
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* args_) {
  struct process_args* args = args_;
  char* file_name = args->file_name;
  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;

  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  success = pcb_success = new_pcb != NULL;

  /* Initialize process control block */
  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    new_pcb->pagedir = NULL;
    t->pcb = new_pcb;

    // Continue initializing the PCB as normal
    t->pcb->main_thread = t;
    strlcpy(t->pcb->process_name, t->name, sizeof t->name);

    t->parent = args->shared_data->parent_pid;
    t->exit_code = -1;
    t->pcb->parent_info = args->shared_data;

    /* Initialize main thread semaphore */
    sema_init(&t->pcb->main_thread_join, 0);

    //Initialize File Descriptor Table
    list_init(&t->pcb->fd_list);
    t->pcb->next_fd = 2;

    list_init(&t->pcb->children);

    //Initialize user operations
    list_init(&t->pcb->user_threads);
    bool exit_status = false;
    list_init(&t->pcb->user_locks);
    list_init(&t->pcb->user_semaphores);

    // Initialize list of join statuses
    list_init(&t->pcb->join_statuses);
  }

  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    asm("fninit; fsave (%0)" : : "g"(&if_.fpu_state));
    success = load(file_name, &if_.eip, &if_.esp, args);
  }
  //Set load_status
  struct process_info* child = t->pcb->parent_info;
  child->load_success = success;
  sema_up(&child->sema);

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;
    free(pcb_to_free);
  }
  /* Clean up. Exit on failure or jump to userspace */
  palloc_free_page(file_name);
  if (!success) {

    sema_up(&child->sema);
    lock_acquire(&child->ref_lock);
    int ref_count = --child->ref_count;
    lock_release(&child->ref_lock);
    if (ref_count == 0) {
      list_remove(&child->elem);
      free(child);
    }
    free(args->argv);
    free(args);
    thread_exit();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */

int process_wait(pid_t child_pid) {
  /* NEW CHANGES */

  int exit_code = -1;
  struct process* p = thread_current()->pcb;
  struct list_elem* e;
  /* Find the child with the given pid in the parent's child list */
  for (e = list_begin(&p->children); e != list_end(&p->children); e = list_next(e)) {
    /* Added checks for wait bad-pid case */
    if (e == NULL)
      return -1;
    struct process_info* child = list_entry(e, struct process_info, elem);
    if (child == NULL)
      return -1;
    if (child->pid == child_pid) {
      /* The process that calls wait has already called wait on pid. That is, a process may wait for any given child at most once.*/
      if (child->has_waiter)
        return -1;

      child->has_waiter = true;

      /* Down semaphore of the shared data with the child */

      sema_down(&child->sema);
      /* When unblocked, return exit code from shared data*/
      /*Decrement reference count and destroy if 0*/
      exit_code = child->exit_code;
      lock_acquire(&child->ref_lock);
      int ref_count = --child->ref_count;
      lock_release(&child->ref_lock);
      if (ref_count == 0) {
        list_remove(e);
        free(child);
      }
      return exit_code;
    }
  }
  return -1;
}

/* Free the current process's resources. */
void process_exit(void) {
  struct thread* cur = thread_current();
  uint32_t* pd;

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;

  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur->pcb;
  cur->pcb = NULL;

  /* NEW CHANGES */
  /* store exit code into data structure shared by PARENT*/
  struct list_elem* e;
  struct process_info* child = pcb_to_free->parent_info;

  child->exit_code = cur->exit_code;
  sema_up(&child->sema);
  /* Decrement reference count of the shared data with the parent and each child, destroy if 0*/
  lock_acquire(&child->ref_lock);
  int ref_count = --child->ref_count;
  lock_release(&child->ref_lock);
  if (ref_count == 0) {
    list_remove(&child->elem);
    free(child);
  }

  e = list_begin(&pcb_to_free->children);
  while (e != list_end(&pcb_to_free->children)) {
    struct list_elem* next = list_next(e);
    struct process_info* child = list_entry(e, struct process_info, elem);
    lock_acquire(&child->ref_lock);
    int ref_count = --child->ref_count;
    lock_release(&child->ref_lock);
    if (ref_count == 0) {
      list_remove(e);
      free(child);
    }

    e = next;
  }

  while (!list_empty(&pcb_to_free->fd_list)) {
    e = list_pop_front(&pcb_to_free->fd_list);
    struct file_entry* entry = list_entry(e, struct file_entry, list_elem);
    if (entry->file != NULL) {
      file_close(entry->file);
    }
    free(entry);
  }

  while (!list_empty(&pcb_to_free->user_locks)) {
    e = list_pop_front(&pcb_to_free->user_locks);
    struct lock* kernel_lock = list_entry(e, struct lock, user_elem);

    free(kernel_lock);
  }

  while (!list_empty(&pcb_to_free->user_semaphores)) {
    e = list_pop_front(&pcb_to_free->user_semaphores);
    struct semaphore* kernel_sema = list_entry(e, struct semaphore, user_elem);

    free(kernel_sema);
  }

  // // wake waiters
  // for (e = list_begin(&pcb_to_free->user_threads); e != list_end(&pcb_to_free->user_threads);
  //      e = list_next(e)) {
  //   struct thread_shared* shared = list_entry(e, struct thread_shared, elem);
  //   if (cur->tid == shared->tid) {
  //     // sema up to allow joining thread to run
  //     sema_up(&shared->sema);
  //     break;
  //   }
  // }

  printf("%s: exit(%d)\n", pcb_to_free->process_name, cur->exit_code);
  free(pcb_to_free);
  file_close(cur->exec);
  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp, struct process_args* args);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp, struct process_args* args) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);

  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }
  file_deny_write(file);
  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp, args))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */

  if (!success)
    file_close(file);
  else
    t->exec = file;
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp, struct process_args* args) {
  char** argv = args->argv;
  int argc = args->argc;

  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success) {
      *esp = PHYS_BASE;

      //Push argument strings onto the stack
      for (int i = argc - 1; i >= 0; i--) {
        *esp -= strlen(argv[i]) + 1;
        memcpy(*esp, argv[i], strlen(argv[i]) + 1);
        argv[i] = *esp;
      }

      //Push argument string pointers onto the stack
      for (int i = argc; i >= 0; i--) {
        *esp -= sizeof(char*);
        memcpy(*esp, &argv[i], sizeof(char*));
      }

      char** argv_ptr = *esp;
      //Align 16 bytes
      unsigned int misalignment = (unsigned int)(*esp) % 16;
      if (misalignment < 8)
        *esp -= misalignment + 8;
      else if (misalignment > 8)
        *esp -= misalignment - 8;

      //Push pointer to argv (argument 1)
      *esp -= sizeof(char**);
      memcpy(*esp, &argv_ptr, sizeof(char**));

      //Push pointer to argc (argument 0)
      *esp -= sizeof(int);
      memcpy(*esp, &argc, sizeof(int));

      //Fake return address
      *esp -= sizeof(void*);
      memset(*esp, 0, sizeof(void*));

    } else
      palloc_free_page(kpage);
  }

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void (**eip)(void), void** esp, void* arg) {
  struct thread* t = thread_current();

  struct thread_wrap* args = (struct thread_wrap*)arg;
  stub_fun sf = args->sf;
  pthread_fun tf = args->tf;
  void* thread_args = args->thread_args;
  //t->pcb = args->pcb;

  // Allocate a page for the stack
  void* kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage == NULL) {
    return false;
  }
  void* uaddr = (void*)PHYS_BASE - PGSIZE;
  bool status = install_page(uaddr, kpage, true);
  while (!status) {
    uaddr -= PGSIZE;
    status = install_page(uaddr, kpage, true);
    if (uaddr <= (void*)0x00000000) {
      break;
    }
  }
  if (!status) {
    palloc_free_page(kpage);
    return false;
  }

  // Start esp at top of stack
  *esp = uaddr + PGSIZE;

  // Push void* arg onto stack and move stack pointer
  *esp -= sizeof(void*);
  memcpy(*esp, &thread_args, sizeof(void*));

  // Push thread function onto stack and move stack pointer
  *esp -= sizeof(pthread_fun);
  memcpy(*esp, &tf, sizeof(pthread_fun*));

  // Align 16 bytes
  unsigned int misalignment = (unsigned int)(*esp) % 16;
  if (misalignment < 8)
    *esp -= misalignment + 8;
  else if (misalignment > 8)
    *esp -= misalignment - 8;

  // Fake return address
  *esp -= sizeof(void*);
  memset(*esp, 0, sizeof(void*));

  // Set eip
  *eip = (void (*)(void))sf;

  return true;
}

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf, pthread_fun tf, void* arg) {
  struct thread* t = thread_current();

  struct thread_wrap* args = malloc(sizeof(struct thread_wrap));
  if (args == NULL) {
    return TID_ERROR;
  }
  args->sf = sf;
  args->tf = tf;
  args->thread_args = arg;
  args->pcb = t->pcb;
  sema_init(&args->sema, 0);

  char* temp = "test";
  tid_t tid = thread_create(temp, PRI_DEFAULT, start_pthread, (void*)args);

  sema_down(&args->sema);
  if (tid == NULL) {
    free(args);
    return TID_ERROR;
  }

  return tid;
}

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* aux) {
  struct thread* t = thread_current();
  struct intr_frame if_;

  bool success;

  struct thread_wrap* args = (struct thread_wrap*)aux;
  stub_fun sf = args->sf;
  pthread_fun tf = args->tf;
  void* thread_args = args->thread_args;
  t->pcb = args->pcb;

  process_activate();

  // set if registers to correct values
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  asm("fninit; fsave (%0)" : : "g"(&if_.fpu_state));

  // setup stack for the thread to run
  success = setup_thread(&if_.eip, &if_.esp, aux);

  if (!success) {
    pthread_exit(if_.esp);
  } else {
    struct thread_shared* child_thread = malloc(sizeof(struct thread_shared));
    if (child_thread == NULL) {
      return TID_ERROR;
    }
    child_thread->exit_code = 0;
    sema_init(&child_thread->sema, 0);
    lock_init(&child_thread->ref_lock);
    child_thread->ref_count = 2;
    child_thread->has_joined = false;
    child_thread->success = false;
    child_thread->tid = t->tid;

    list_push_back(&t->pcb->user_threads, &child_thread->elem);
  }

  sema_up(&args->sema);

  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid) {
  struct thread* t = thread_current();

  if (tid == t->tid) {
    return TID_ERROR;
  }

  if (tid == t->pcb->main_thread->tid) {
    sema_down(&t->pcb->main_thread_join);
    return tid;
  }

  struct list_elem* e;
  for (e = list_begin(&t->pcb->user_threads); e != list_end(&t->pcb->user_threads);
       e = list_next(e)) {
    if (e == NULL) {
      return TID_ERROR;
    }
    struct thread_shared* shared = list_entry(e, struct thread_shared, elem);
    if (shared == NULL) {
      return TID_ERROR;
    }
    if (shared->tid == tid && !shared->has_joined) {
      //lock_acquire(&shared->ref_lock);
      shared->has_joined = true;
      //lock_release(&shared->ref_lock);
      sema_down(&shared->sema);

      list_remove(e);
      free(shared);

      return tid;
    }
  }
  return TID_ERROR;
}

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void* esp) {
  /*
   pthread_exit should deallocate the user stack first (involves removing the page directory mapping and freeing the 
   palloced page), then wake waiters, then kill this thread. Must deallocate the stack first, 
   so other new threads can use it.*/

  struct thread* t = thread_current();

  uint8_t* kpage = pagedir_get_page(t->pcb->pagedir, pg_round_down(esp));

  // clear the page directoy mapping by freeing the palloced page
  pagedir_clear_page(t->pcb->pagedir, pg_round_down(esp));

  // remove the page directory mapping by freeing the page
  palloc_free_page(kpage);

  //wake waiters
  struct list_elem* e;
  for (e = list_begin(&t->pcb->user_threads); e != list_end(&t->pcb->user_threads);
       e = list_next(e)) {
    struct thread_shared* shared = list_entry(e, struct thread_shared, elem);
    if (t->tid == shared->tid) {
      // sema up to allow joining thread to run
      sema_up(&shared->sema);
      break;
    }
  }

  // kill this thread
  thread_exit();

  NOT_REACHED();
}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {
  struct thread* t = thread_current();
  /* First wake any waiters on main thread */
  sema_up(&t->pcb->main_thread_join);

  /* Iterate through all user threads and join them */
  struct list_elem* e = list_begin(&t->pcb->user_threads);
  while (e != list_end(&t->pcb->user_threads)) {
    struct thread_shared* shared = list_entry(e, struct thread_shared, elem);
    e = list_next(e);

    if (shared != NULL) {
      /* Try to join if not already joined */
      lock_acquire(&shared->ref_lock);
      if (!shared->has_joined) {
        lock_release(&shared->ref_lock);
        /* Wait for thread to complete */
        sema_down(&shared->sema);
        /* Now that thread is done, we can safely remove and free */
        list_remove(&shared->elem);
        free(shared);
      } else {
        lock_release(&shared->ref_lock);
      }
    }
  }

  /* After all threads are joined, terminate the process */
  t->exit_code = 0;
  process_exit();
  NOT_REACHED();
}

struct file_entry* find_file_by_fd(struct list* file_list, int fd) {
  struct list_elem* e;
  for (e = list_begin(file_list); e != list_end(file_list); e = list_next(e)) {
    struct file_entry* f = list_entry(e, struct file_entry, list_elem);
    if (f->fd == fd) {
      return f;
    }
  }

  return NULL;
}