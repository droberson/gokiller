/* This is based off of https://github.com/rootfoo/rootkit */

/* this will execute "/root/cp.sh <PID>" when it detects golang executions */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/thread_info.h>
#include <linux/delay.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/buffer_head.h>
#include <asm/paravirt.h>
#include <asm/pgtable.h>
#include <asm/segment.h>
#include <asm/uaccess.h>

#define DEBUG
#undef HIDE_MODULE
#define LOG_KILLS

unsigned long *syscall_table = NULL;
pte_t *pte;

static int send_sig_info(int sig, struct siginfo *info, struct task_struct *p);

/* from: /usr/src/linux-headers-$(uname -r)/include/linux/syscalls.h */
asmlinkage long (*real_mmap)(unsigned long addr, unsigned long len, unsigned long prot, unsigned int flags, unsigned int fd, unsigned int pgoff);

asmlinkage long new_mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned int flags, unsigned int fd, unsigned int pgoff) {
  struct siginfo info;
  int ret;
  struct path p;
  char exe[16];
  char buf[256];
  char *path = ERR_PTR(-ENOENT);
  char *b[3];

  /*
   * All golang binaries I've observed make this specific call to mmap()
   * early in their execution. Every non-golang binary I have observed does
   * not make this mmap() call. I am using this as a terrible indicator of
   * golang execution.
   *
   * mmap(0xc000000000, 65536, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
   */
  if ((addr == 0xc000000000) && (len == 65536) && (fd == -1) && (pgoff == 0)) {
#ifdef LOG_KILLS
    snprintf(exe, sizeof(exe), "/proc/%d/exe", current->pid);
    ret = kern_path(exe, LOOKUP_FOLLOW, &p);
    if (ret < 0) {
      pr_info("kern_path error: %d\n", ret);
    } else {
      path = d_path(&p, buf, sizeof(buf));
    }
    if (IS_ERR(path)) {
      pr_info("GOKILLER sending SIGKILL to %d\n", current->pid);
    } else {
      if (strcmp(path, "/usr/lib/snapd/snapctl") == 0) {
	pr_info("GOKILLER just kidding.. %s is whitelisted\n", path);
	goto end;
      }
      pr_info("GOKILLER sending SIGKILL to %d %s\n", current->pid, path);
    }
#endif

    snprintf(buf, sizeof(buf), "%d", current->pid);
    b[0] = "/root/cp.sh";
    b[1] = buf;
    b[2] = NULL;
    call_usermodehelper("/root/cp.sh", b, NULL, UMH_WAIT_PROC);

    memset(&info, 0, sizeof(struct siginfo));
    info.si_signo = SIGKILL;
    ret = send_sig_info(SIGKILL, &info, current);
    if (ret < 0) {
#ifdef DEBUG
      pr_info("Error killing process: %d\n", ret);
#endif
    }
    return -1;
  }

 end:
  return real_mmap(addr, len, prot, flags, fd, pgoff);
}


void module_hide(void) {
  list_del(&THIS_MODULE->list);             //remove from procfs
  kobject_del(&THIS_MODULE->mkobj.kobj);    //remove from sysfs
  THIS_MODULE->sect_attrs = NULL;
  THIS_MODULE->notes_attrs = NULL;
}


void hijack_mmap(void) {
  unsigned int level;
  syscall_table = NULL;

  syscall_table = (void *)kallsyms_lookup_name("sys_call_table");
  pte = lookup_address((long unsigned int)syscall_table, &level);

#ifdef DEBUG
  pr_info("GOKILLER syscall_table is at %p\n", syscall_table);
  pr_info("GOKILLER PTE address at %p\n", &pte);
#endif

  if (syscall_table != NULL) {
    write_cr0(read_cr0() & (~ 0x10000));
    real_mmap = (void *)syscall_table[__NR_mmap];
    syscall_table[__NR_mmap] = &new_mmap;
    write_cr0(read_cr0() | 0x10000);
#ifdef DEBUG
    pr_info("GOKILLER mmap is at %p\n", real_mmap);
    pr_info("GOKILLER syscall_table[__NR_mmap] hooked\n");
#endif
  } else {
#ifdef DEBUG
    printk(KERN_EMERG "GOKILLER error hooking mmap\n");
#endif
  }
}


void un_hijack_mmap(void) {
  if (syscall_table != NULL) {
    pte->pte |= _PAGE_RW;
    syscall_table[__NR_mmap] = real_mmap;
    pte->pte &= ~_PAGE_RW;
    pr_info("GOKILLER mmap unhooked\n");
  } else {
    pr_info("GOKILLER syscall_table is NULL\n");
  }
}


static int __init my_init(void) {
#ifdef DEBUG
  pr_info("GOKILLER module loaded at 0x%p\n", my_init);
#endif

#ifdef HIDE_MODULE
  module_hide();
#endif

  hijack_mmap();

  return 0;
}


static void __exit my_exit(void) {
  un_hijack_mmap();
#ifdef DEBUG
  pr_info("GOKILLER unloaded from 0x%p\n", my_exit);
#endif
}


module_init(my_init);
module_exit(my_exit);


MODULE_AUTHOR("Daniel Roberson");
MODULE_LICENSE("GPL v2");

