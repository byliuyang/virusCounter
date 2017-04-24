#include <asm/current.h>
#include <asm/errno.h>
#include <asm/uaccess.h>
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/types.h>

#define ROOT_USER 0
#define PROTECTED_USER 1001
#define SCEDULER_PID 1

unsigned long **sys_call_table;

asmlinkage long (*ref_sys_cs3013_syscall2)(void);

/*
 * Do depth first search on the process tree
 * @param parent_task The parent task struct to search for
 * @param target_pid The target process id to search for
 */
struct task_struct *deepth_first_search(struct task_struct *parent_task,
                                        unsigned short target_pid) {
  struct list_head *list;
  struct task_struct *child_task;
  struct task_struct *target_task = NULL;

  // Check parent's process id
  if (parent_task->pid == target_pid) {
    return parent_task;
  }

  // Iterate through children
  list_for_each(list, &parent_task->children) {
    child_task = list_entry(list, struct task_struct, sibling);
    // Perform DFS on each child
    target_task = deepth_first_search(child_task, target_pid);
    // Return when find it
    if (target_task)
      return target_task;
  }

  // Return NULL when didn't find the target process
  return target_task;
}

/*
 * This method did iterative depth first search to find target pid.
 * @param src_task The begining task to search from
 * @param init The root task to end at.
 * @param target_pid The target process id to search for
 */
struct task_struct *current_search(struct task_struct *src_task,
                                   struct task_struct *init,
                                   unsigned short target_pid) {
  struct task_struct *task;
  struct task_struct *loop;
  struct list_head *list;
  struct task_struct *target_task = NULL;

  // Seach all current's children
  target_task = deepth_first_search(src_task, target_pid);
  // Find target process on current or its children
  if (target_task)
    return target_task;

  // Loop through parent layer on the tree
  for (loop = src_task; loop != init; loop = loop->parent) {
    // Find target process
    if (loop->pid == target_pid) {
      return loop;
    }

    // Iterate through sibling and search through its children
    list_for_each(list, &loop->sibling) {
      task = list_entry(list, struct task_struct, sibling);

      // Do not perform DFS on scheduler
      if (task->pid > SCEDULER_PID) {
        // Seach through children tree
        target_task = deepth_first_search(task, target_pid);
        // Return when find the target
        if (target_task)
          return target_task;
      }
    }
  }

  // Return NULL when didn't find the target process
  return target_task;
}

/*
 * Check the permission of caller
 * param
 */
int check_permission(unsigned short caller_uid, unsigned short target_uid,
                     struct task_struct *task) {
  if ((caller_uid == ROOT_USER) ||
      ((task->cred->uid.val == caller_uid) && (target_uid == PROTECTED_USER)))
    // When is root user, not restriction
    // When is normal user, the user can only access the procces that belongs to
    // him
    return 1;
  // No permission
  return 0;
}

asmlinkage long new_sys_cs3013_syscall2(unsigned short *target_pid,
                                        unsigned short *target_uid) {
  unsigned short pid_buf, uid_buf;
  int uid_flag;
  int pid_flag;
  struct task_struct *target_task = NULL;

  uid_flag = copy_from_user(&uid_buf, target_uid, sizeof(unsigned short));
  pid_flag = copy_from_user(&pid_buf, target_pid, sizeof(unsigned short));

  // Validate the system call inputs
  if (uid_flag || pid_flag) {
    return -EFAULT;
  }

  target_task = current_search(current, &init_task, pid_buf);
  if (target_task) {
    // Find the target process
    if (check_permission(current->cred->uid.val, uid_buf, target_task)) {
      // Have permission

      // Set up target loginuid
      target_task->loginuid.val = uid_buf;

      printk(KERN_INFO "Successfully changed process[%d]'s loginuid to '[%u]\n",
             target_task->pid, target_task->loginuid.val);

      return 0;
    }

    printk(KERN_INFO "User [%u] has no permission to process[%u]\n",
           current->cred->uid.val, target_task->pid);
    return -EFAULT;
  }

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
  ref_sys_cs3013_syscall2 = (void *)sys_call_table[__NR_cs3013_syscall2];

  /* Replace the existing system calls */
  disable_page_protection();

  sys_call_table[__NR_cs3013_syscall2] =
      (unsigned long *)new_sys_cs3013_syscall2;

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
  sys_call_table[__NR_cs3013_syscall2] =
      (unsigned long *)ref_sys_cs3013_syscall2;
  enable_page_protection();

  printk(KERN_INFO "Unloaded interceptor!\n");
}

MODULE_LICENSE("GPL");
module_init(interceptor_start);
module_exit(interceptor_end);
