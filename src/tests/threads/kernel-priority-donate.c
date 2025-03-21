/* Test that verifies kernel implementation uses base priority for semaphores
   rather than effective (donated) priority. */

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/thread.h"

static thread_func A_thread_func;
static thread_func B_thread_func;
static thread_func C_thread_func;
static thread_func D_thread_func;

/* Shared synchronization primitives */
static struct lock lock;
static struct semaphore sema;

/* Structure to pass multiple parameters to threads */
struct thread_params {
  struct lock* lock;
  struct semaphore* sema;
};

void test_kernel_priority_donate(void) {
  struct thread_params params;

  /* Initialize synchronization primitives */
  lock_init(&lock);
  sema_init(&sema, 0);

  params.lock = &lock;
  params.sema = &sema;

  /* Create A with priority low */
  thread_create("A", PRI_MIN, A_thread_func, &params);

  /* Wait for test to complete */
  timer_sleep(200);
}

static void A_thread_func(void* params_) {
  struct thread_params* params = params_;

  msg("A: Creating B and C");

  /* Create B (priority medium) and C (priority high) */
  thread_create("B", PRI_MIN + 3, B_thread_func, params);
  thread_create("C", PRI_MIN + 5, C_thread_func, params);

  /* Yield to let B and C run */
  thread_yield();

  /* Both B and C should now be blocked */
  msg("A: Both B and C should be blocked. Calling first sema_up");
  sema_up(params->sema);

  /* Yield to let the unblocked thread run */
  thread_yield();

  msg("A: Calling second sema_up");
  sema_up(params->sema);
}

static void B_thread_func(void* params_) {
  struct thread_params* params = params_;

  msg("B: Acquiring lock");
  lock_acquire(params->lock);

  msg("B: Creating D");
  thread_create("D", PRI_MIN + 20, D_thread_func, params);

  msg("B: Downing semaphore");
  sema_down(params->sema);

  /* Print B when we wake up */
  msg("B");

  msg("B: Releasing lock");
  lock_release(params->lock);
}

static void C_thread_func(void* params_) {
  struct thread_params* params = params_;

  msg("C: Downing semaphore");
  sema_down(params->sema);

  /* Print C when we wake up */
  msg("C");
}

static void D_thread_func(void* params_) {
  struct thread_params* params = params_;

  msg("D: Attempting to acquire lock");
  lock_acquire(params->lock);
  msg("D: Acquired lock");
  lock_release(params->lock);
  msg("D: Released lock");
}