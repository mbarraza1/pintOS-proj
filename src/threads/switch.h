#ifndef THREADS_SWITCH_H
#define THREADS_SWITCH_H

#ifndef __ASSEMBLER__
/* switch_thread()'s stack frame. */
struct switch_threads_frame {
  uint8_t fpu_state[108]; /*  0: Saved FPU state */
  uint32_t edi;           /*  108: Saved %edi. */
  uint32_t esi;           /*  112: Saved %esi. */
  uint32_t ebp;           /*  116: Saved %ebp. */
  uint32_t ebx;           /* 120: Saved %ebx. */
  void (*eip)(void);      /* 124: Return address. */
  struct thread* cur;     /* 128: switch_threads()'s CUR argument. */
  struct thread* next;    /* 132: switch_threads()'s NEXT argument. */
};

/* Switches from CUR, which must be the running thread, to NEXT,
   which must also be running switch_threads(), returning CUR in
   NEXT's context. */
struct thread* switch_threads(struct thread* cur, struct thread* next);

/* Stack frame for switch_entry(). */
struct switch_entry_frame {
  void (*eip)(void);
};

void switch_entry(void);

/* Pops the CUR and NEXT arguments off the stack, for use in
   initializing threads. */
void switch_thunk(void);
#endif

/* Offsets used by switch.S. */
#define SWITCH_CUR 128
#define SWITCH_NEXT 132

#endif /* threads/switch.h */
