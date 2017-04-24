#include <asm/uaccess.h>
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/syscalls.h>

unsigned long **sys_call_table;

// Keep pointer for original system call
asmlinkage long (*ref_sys_cs3013_syscall3)(void);

/*
 * This method replaces the original system call
 * @param target_pid The target pid to search for
 * @param actual_uid The login uid found for target process
 */
asmlinkage long new_sys_cs3013_syscall3(unsigned short *target_pid,
                                        unsigned short *actual_uid) {
  struct list_head *head;   // Keep task list head
  struct list_head *loop;   // Keep loop list head
  struct task_struct *task; // Keep founded task
  unsigned short pid_buf;   // Keep target pid
  unsigned short uid_buf;   // Keep login uid founded

  // Copy and validate pointer passed from user space to kernel space
  if (copy_from_user(&pid_buf, target_pid, sizeof(unsigned short)))
    return -EFAULT;

  // Check for current process's pid
  if (current->pid == pid_buf) {
    uid_buf = current->loginuid.val;
    printk(KERN_INFO "Find loginuid %d for process [%d]\n", uid_buf, pid_buf);

    if (copy_to_user(actual_uid, &uid_buf, sizeof(unsigned short)))
      return -EFAULT;
    return 0;
  }
  // Loop end at current
  head = &(current->tasks);
  loop = head;
  // Loop through all tasks
  do {
    // Get task struct
    task = list_entry(loop, struct task_struct, tasks);
    if (task->pid == pid_buf) {
      // Find the target task, get it's loginuid
      uid_buf = task->loginuid.val;
      // Print trace information to system log
      printk(KERN_INFO "Find loginuid %d for process [%d]\n", uid_buf, pid_buf);

      // Copy login uid to caller
      if (copy_to_user(actual_uid, &uid_buf, sizeof(unsigned short)))
        return -EFAULT;
      return 0;
    }

    // Go to next task
    loop = loop->next;

    // End when look back to current
  } while (loop != head);

  // Could find target process
  printk(KERN_INFO "Target process[%d] is not running\n", pid_buf);
  return -EFAULT;
}

static unsigned long **find_sys_call_table(void) {
  unsigned long int offset = PAGE_OFFSET;
  unsigned long **sct;

  while (offset < ULLONG_MAX) {
    sct = (unsigned long **)offset;

    if (sct[__NR_close] == (unsigned long *)sys_close) {
      printk(KERN_INFO "Interceptor: Found syscall table at address: 0x%02lX\n",
             (unsigned long)sct);
      return sct;
    }

    offset += sizeof(void *);
  }

  return NULL;
}

static void disable_page_protection(void) {
  /*
    Control Register 0 (cr0) governs how the CPU operates.

    Bit #16, if set, prevents the CPU from writing to memory marked as
    read only. Well, our system call table meets that description.
    But, we can simply turn off this bit in cr0 to allow us to make
    changes. We read in the current value of the register (32 or 64
    bits wide), and AND that with a value where all bits are 0 except
    the 16th bit (using a negation operation), causing the write_cr0
    value to have the 16th bit cleared (with all other bits staying
    the same. We will thus be able to write to the protected memory.

    It's good to be the kernel!
  */
  write_cr0(read_cr0() & (~0x10000));
}

static void enable_page_protection(void) {
  /*
   See the above description for cr0. Here, we use an OR to set the
   16th bit to re-enable write protection on the CPU.
  */
  write_cr0(read_cr0() | 0x10000);
}

static int __init interceptor_start(void) {
  /* Find the system call table */
  if (!(sys_call_table = find_sys_call_table())) {
    /* Well, that didn't work.
       Cancel the module loading step. */
    return -1;
  }

  /* Store a copy of all the existing functions */
  ref_sys_cs3013_syscall3 = (void *)sys_call_table[__NR_cs3013_syscall3];

  /* Replace the existing system calls */
  disable_page_protection();

  sys_call_table[__NR_cs3013_syscall3] =
      (unsigned long *)new_sys_cs3013_syscall3;

  enable_page_protection();

  /* And indicate the load was successful */
  printk(KERN_INFO "Loaded interceptor!\n");

  return 0;
}

static void __exit interceptor_end(void) {
  /* If we don't know what the syscall table is, don't bother. */
  if (!sys_call_table)
    return;

  /* Revert all system calls to what they were before we began. */
  disable_page_protection();
  sys_call_table[__NR_cs3013_syscall3] =
      (unsigned long *)ref_sys_cs3013_syscall3;
  enable_page_protection();

  printk(KERN_INFO "Unloaded interceptor!\n");
}

MODULE_LICENSE("GPL");
module_init(interceptor_start);
module_exit(interceptor_end);
