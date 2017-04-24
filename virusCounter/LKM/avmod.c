#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#define MAL_CODE "VIRUS" // Virus string to detect
#define REG_USER 1000    // Regular user's uid

// Function prototyes
char tolower(char c);
char *tolowerstr(const char *str);

unsigned long **sys_call_table;

// Keep pointer of original system calls
asmlinkage long (*ref_sys_open)(const char *pathname, int flags, mode_t mode);
asmlinkage long (*ref_sys_close)(int fildes);
asmlinkage long (*ref_sys_read)(int fildes, void *buffer, size_t count);
asmlinkage long (*ref_sys_cs3013_syscall1)(void);

/*
* This function convert a character to lowercase
* @return The uppercase of a character
*/
char tolower(char c) {
  if ((int)c >= 0x41 && (int)c <= 0x5A)
    return c + 0x20;
  return c;
}

/*
* This function convert a string to lowercase
* @return Pointer of lowercase string
*/
char *tolowerstr(const char *str) {
  char *newstr; // Pointer of lowercase string generated
  int i;        // Loop counter
  int str_len;  // Length of string

  // Check for NULL pointer
  if (!str)
    return NULL;

  // Include '\0'
  str_len = (strlen(str) + 1);

  // Allocate memory for new string, no fail
  newstr = kmalloc(str_len * sizeof(char *), __GFP_NOFAIL);

  // Fail to allocate memory
  if (!newstr)
    return NULL;

  // Copy each character to new string and convert it to lower case
  i = 0;
  for (i = 0; i < str_len; i++) {
    newstr[i] = tolower(str[i]);
  }

  // Add terminator for new string
  newstr[i + 1] = '\0';

  // Return pointer to lower case string
  return newstr;
}

asmlinkage long new_sys_cs3013_syscall1(void) {
  printk(
      KERN_INFO
      "\"’Hello world?!’ More like ’Goodbye, world!’ EXTERMINATE!\" -- Dalek");
  return 0;
}

/*
 * This method replaces the original open system call
 * @param pathname The pathname of file
 * @param flag The flag
 * @param mode The mode
 * @return file discriptor
 */
asmlinkage long new_sys_open(const char *pathname, int flags, mode_t mode) {
  // When open file
  int uid;                 // Caller's user id
  uid = current_uid().val; // Get caller's uid
  if (uid >= REG_USER) {
    // Regular user, print message to system log
    printk(KERN_INFO "User %d is opening file: %s\n", uid, pathname);
  }
  // Call the original system call
  return ref_sys_open(pathname, flags, mode);
}

/*
 * This method replaces the original close system call
 * @return file discriptor
 */
asmlinkage long new_sys_close(int fd) {
  // When close file
  int uid;                 // Caller's user id
  uid = current_uid().val; // Get caller's uid
  if (uid >= REG_USER) {
    // Regular user, print message to system log
    printk(KERN_INFO "User %d is closing file: %d\n", uid, fd);
  }
  // Call the original system call
  return ref_sys_close(fd);
}

asmlinkage long new_sys_read(int fd, void *buf, size_t count) {
  // When close file
  int uid;                    // Caller's user id
  char *lowercode, *lowerbuf; // Lower case virus code and buffer
  uid = current_uid().val;    // Get caller's uid
  if (uid >= REG_USER) {
    // Regular user, get lower case virus code and buffer
    lowercode = tolowerstr(MAL_CODE);
    lowerbuf = tolowerstr(buf);

    // Search virus code in the buffer
    if (strstr(lowerbuf, lowercode)) {
      // Find virus code in the buffer
      printk(KERN_INFO "User %d read from file descriptor %d, but that read "
                       "contained malicious code.\n",
             uid, fd);
    } else {
      // The buffer is safe
      printk(KERN_INFO "User %d read from file descriptor %d\n", uid, fd);
    }
    // Free memory allocated for lower case conversions
    kfree(lowercode);
    kfree(lowerbuf);
  }

  // Call the original system call
  return ref_sys_read(fd, buf, count);
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
  ref_sys_cs3013_syscall1 = (void *)sys_call_table[__NR_cs3013_syscall1];
  ref_sys_open = (void *)sys_call_table[__NR_open];
  ref_sys_close = (void *)sys_call_table[__NR_close];
  ref_sys_read = (void *)sys_call_table[__NR_read];

  /* Replace the existing system calls */
  disable_page_protection();

  sys_call_table[__NR_cs3013_syscall1] =
      (unsigned long *)new_sys_cs3013_syscall1;

  sys_call_table[__NR_open] = (unsigned long *)new_sys_open;
  sys_call_table[__NR_close] = (unsigned long *)new_sys_close;
  sys_call_table[__NR_read] = (unsigned long *)new_sys_read;

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
  sys_call_table[__NR_cs3013_syscall1] =
      (unsigned long *)ref_sys_cs3013_syscall1;

  sys_call_table[__NR_open] = (unsigned long *)ref_sys_open;
  sys_call_table[__NR_close] = (unsigned long *)ref_sys_close;
  sys_call_table[__NR_read] = (unsigned long *)ref_sys_read;
  enable_page_protection();

  printk(KERN_INFO "Unloaded interceptor!\n");
}

MODULE_LICENSE("GPL");
module_init(interceptor_start);
module_exit(interceptor_end);
