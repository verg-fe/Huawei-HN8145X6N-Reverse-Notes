/*
 * hi1152_rf_tuner.c - Standalone HiSilicon Hi1152 RF Calibration & SRAM Tuner
 * Target Kernel: Linux 5.10.0 SMP ARMv7 (no kernel headers required)
 */

typedef unsigned int size_t;
typedef long long loff_t;
typedef int ssize_t;

struct proc_dir_entry;
struct seq_file;
struct inode;
struct file;

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

extern struct proc_dir_entry *proc_create(const char *name, unsigned short mode, struct proc_dir_entry *parent, const struct proc_ops *proc_ops);
extern void proc_remove(struct proc_dir_entry *de);
extern int single_open(struct file *, int (*)(struct seq_file *, void *), void *);
extern ssize_t seq_read(struct file *, char *, size_t, loff_t *);
extern loff_t seq_lseek(struct file *, loff_t, int);
extern int single_release(struct inode *, struct file *);
extern int seq_printf(struct seq_file *m, const char *fmt, ...);
extern unsigned long arm_copy_from_user(void *to, const void *from, unsigned long n);
extern int printk(const char *fmt, ...);

/* HWWIFI2_PLAT.ko exported symbols */
extern unsigned char g_dev_custom_info[] __attribute__((weak));
extern int oal_pcie_devca_to_hostva(unsigned int chip_id, unsigned int devca, unsigned long long *hostva) __attribute__((weak));

__attribute__((section(".modinfo"), used)) static const char __mod_license[] = "license=GPL";
__attribute__((section(".modinfo"), used)) static const char __mod_name[] = "name=hi1152_rf_tuner";
__attribute__((section(".modinfo"), used)) static const char __mod_vermagic[] = "vermagic=5.10.0 SMP mod_unload ARMv7 \0";

__asm__(".section .plt, \"ax\", %progbits\n.byte 0\n");
__asm__(".section .init.plt, \"a\", %progbits\n.byte 0\n");

#define CUSTOM_DEVCA_BASE 0x1b2830U
#define CUSTOM_LEN        0x978U
#define FACTORY_MAX_PWR   0x00dc00e6U

static struct proc_dir_entry *tuner_entry = (void *)0;
static unsigned int g_off = 0x28U;
static unsigned int g_last_val = FACTORY_MAX_PWR;

/* Last operation telemetry */
static int g_last_cmd = 0; /* 0=none, 1=set_max, 2=scan_sram, 3=read_sram, 4=write_sram */
static int g_last_rc = 0;
static unsigned int g_last_p2g = 0;
static unsigned int g_last_p5g = 0;
static unsigned int g_last_new_val = 0;
static unsigned int g_last_host_rb = 0;
static unsigned int g_last_c0_rb = 0;
static unsigned int g_last_c1_rb = 0;
static int g_last_c0_ret = -1;
static int g_last_c1_ret = -1;

/* Cached scan_sram output */
static unsigned int g_scan_chip = 0;
static unsigned int g_scan_start = 0;
static unsigned int g_scan_len = 0;
static unsigned int g_scan_target = 0;
static unsigned int g_scan_scanned = 0;
static unsigned int g_scan_skipped = 0;
static unsigned int g_scan_hits_cnt = 0;
static unsigned int g_scan_hits[16];

/* Cached read_sram output */
static unsigned int g_read_chip = 0;
static unsigned int g_read_addr = 0;
static unsigned int g_read_nwords = 0;
static unsigned int g_read_vals[16];
static int g_read_rets[16];

static const char *skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

static int starts_with_word(const char *s, const char *prefix, const char **rest) {
    while (*prefix) {
        if (*s != *prefix) return 0;
        s++;
        prefix++;
    }
    if (*s != '\0' && *s != ' ' && *s != '\t') return 0;
    *rest = skip_ws(s);
    return 1;
}

static int parse_dec(const char *p, unsigned int *out, const char **next) {
    unsigned int v = 0;
    int any = 0;
    p = skip_ws(p);
    while (*p >= '0' && *p <= '9') {
        v = v * 10U + (unsigned int)(*p - '0');
        p++;
        any = 1;
    }
    if (!any) return -1;
    *out = v;
    if (next) *next = p;
    return 0;
}

static int parse_hex(const char *p, unsigned int *out, const char **next) {
    unsigned int v = 0;
    int any = 0;
    p = skip_ws(p);
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }
    while (1) {
        char c = *p;
        unsigned int d;
        if (c >= '0' && c <= '9') d = (unsigned int)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (unsigned int)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (unsigned int)(c - 'A' + 10);
        else break;
        v = (v << 4) | d;
        p++;
        any = 1;
    }
    if (!any) return -1;
    *out = v;
    if (next) *next = p;
    return 0;
}

static void dump_custom_window(struct seq_file *m, const char *tag, volatile const unsigned int *base) {
    seq_printf(m, "%s [+0x18..+0x30]: %08x %08x %08x %08x | +0x28=%08x | %08x %08x\n",
               tag,
               base[0x18 >> 2], base[0x1c >> 2], base[0x20 >> 2], base[0x24 >> 2],
               base[0x28 >> 2], base[0x2c >> 2], base[0x30 >> 2]);
}

static int tuner_show(struct seq_file *m, void *v) {
    unsigned int chip;
    (void)v;

    seq_printf(m, "=== HI1152_RF_TUNER ===\n");
    seq_printf(m, "g_off=0x%x g_last_val=0x%08x\n", g_off, g_last_val);

    if (g_dev_custom_info) {
        volatile const unsigned int *h = (volatile const unsigned int *)g_dev_custom_info;
        seq_printf(m, "host g_dev_custom_info=%p\n", g_dev_custom_info);
        dump_custom_window(m, "host", h);
    } else {
        seq_printf(m, "host g_dev_custom_info=NULL\n");
    }

    if (oal_pcie_devca_to_hostva) {
        for (chip = 0; chip < 2; chip++) {
            unsigned long long va = 0;
            int ret = oal_pcie_devca_to_hostva(chip, CUSTOM_DEVCA_BASE, &va);
            unsigned int va32 = (unsigned int)va;
            seq_printf(m, "chip%u devca=0x%x ret=%d hostva=0x%x\n", chip, CUSTOM_DEVCA_BASE, ret, va32);
            if (ret == 0 && va32 != 0) {
                volatile const unsigned int *p = (volatile const unsigned int *)va32;
                if (chip == 0) dump_custom_window(m, "chip0", p);
                else dump_custom_window(m, "chip1", p);

                if (p[0x28 >> 2] != g_last_val) {
                    unsigned int off;
                    int found = 0;
                    seq_printf(m, "chip%u +0x28 (0x%08x) != expected 0x%08x, scanning 0..0x974 for 0x%08x:",
                               chip, p[0x28 >> 2], FACTORY_MAX_PWR, FACTORY_MAX_PWR);
                    for (off = 0; off < CUSTOM_LEN; off += 4) {
                        if (p[off >> 2] == FACTORY_MAX_PWR) {
                            seq_printf(m, " +0x%x", off);
                            found++;
                        }
                    }
                    if (!found) seq_printf(m, " none");
                    seq_printf(m, "\n");
                }
            }
        }
    } else {
        seq_printf(m, "oal_pcie_devca_to_hostva=NULL\n");
    }

    seq_printf(m, "last_op cmd=%d rc=%d p2g=%u p5g=%u new=0x%08x host_rb=0x%08x c0(ret=%d,rb=0x%08x) c1(ret=%d,rb=0x%08x)\n",
               g_last_cmd, g_last_rc, g_last_p2g, g_last_p5g, g_last_new_val,
               g_last_host_rb, g_last_c0_ret, g_last_c0_rb, g_last_c1_ret, g_last_c1_rb);

    if (g_last_cmd == 2) {
        unsigned int i;
        seq_printf(m, "scan_sram chip=%u start=0x%x len=0x%x target=0x%08x scanned=%u skipped=%u hits=%u:",
                   g_scan_chip, g_scan_start, g_scan_len, g_scan_target,
                   g_scan_scanned, g_scan_skipped, g_scan_hits_cnt);
        for (i = 0; i < g_scan_hits_cnt; i++) {
            seq_printf(m, " 0x%x", g_scan_hits[i]);
        }
        seq_printf(m, "\n");
    } else if (g_last_cmd == 3) {
        unsigned int i;
        seq_printf(m, "read_sram chip=%u start=0x%x n=%u:\n", g_read_chip, g_read_addr, g_read_nwords);
        for (i = 0; i < g_read_nwords; i++) {
            seq_printf(m, "  0x%08x (ret=%d): 0x%08x\n", g_read_addr + (i << 2), g_read_rets[i], g_read_vals[i]);
        }
    }

    return 0;
}

static int tuner_open(struct inode *inode, struct file *file) {
    (void)inode;
    return single_open(file, tuner_show, (void *)0);
}

static void handle_set_max(const char *args) {
    unsigned int p2g = 0, p5g = 0;
    const char *p = args;
    unsigned int new_val, cur_host;
    volatile unsigned int *hptr;
    unsigned long long va0 = 0, va1 = 0;

    g_last_cmd = 1;
    if (parse_dec(p, &p2g, &p) != 0 || parse_dec(p, &p5g, &p) != 0) {
        g_last_rc = -22;
        return;
    }
    g_last_p2g = p2g;
    g_last_p5g = p5g;

    if (p2g < 150U || p2g > 300U || p5g < 150U || p5g > 300U) {
        g_last_rc = -34;
        return;
    }
    if (!g_dev_custom_info || !oal_pcie_devca_to_hostva) {
        g_last_rc = -38;
        return;
    }

    hptr = (volatile unsigned int *)(g_dev_custom_info + g_off);
    cur_host = *hptr;
    if (cur_host != FACTORY_MAX_PWR && cur_host != g_last_val) {
        g_last_host_rb = cur_host;
        g_last_rc = -1;
        printk("[HI1152_RF_TUNER] Safety abort: host+0x%x=0x%08x (expected 0x%08x or 0x%08x)\n",
               g_off, cur_host, FACTORY_MAX_PWR, g_last_val);
        return;
    }

    new_val = (p5g << 16) | p2g;
    g_last_new_val = new_val;

    *hptr = new_val;
    g_last_c0_ret = oal_pcie_devca_to_hostva(0U, CUSTOM_DEVCA_BASE + g_off, &va0);
    if (g_last_c0_ret == 0 && (unsigned int)va0 != 0) {
        *(volatile unsigned int *)(unsigned int)va0 = new_val;
    }
    g_last_c1_ret = oal_pcie_devca_to_hostva(1U, CUSTOM_DEVCA_BASE + g_off, &va1);
    if (g_last_c1_ret == 0 && (unsigned int)va1 != 0) {
        *(volatile unsigned int *)(unsigned int)va1 = new_val;
    }

    __asm__ volatile("dsb sy" ::: "memory");

    g_last_host_rb = *hptr;
    g_last_c0_rb = (g_last_c0_ret == 0 && (unsigned int)va0 != 0) ? *(volatile unsigned int *)(unsigned int)va0 : 0xdeadbeefU;
    g_last_c1_rb = (g_last_c1_ret == 0 && (unsigned int)va1 != 0) ? *(volatile unsigned int *)(unsigned int)va1 : 0xdeadbeefU;
    g_last_val = new_val;
    g_last_rc = 0;

    printk("[HI1152_RF_TUNER] set_max p2g=%u p5g=%u (0x%08x): host=0x%08x c0(ret=%d)=0x%08x c1(ret=%d)=0x%08x\n",
           p2g, p5g, new_val, g_last_host_rb, g_last_c0_ret, g_last_c0_rb, g_last_c1_ret, g_last_c1_rb);
}

static void handle_scan_sram(const char *args) {
    unsigned int chip = 0, start = 0, len = 0, target = 0;
    const char *p = args;
    unsigned int addr, end;

    g_last_cmd = 2;
    if (parse_dec(p, &chip, &p) != 0 ||
        parse_hex(p, &start, &p) != 0 ||
        parse_hex(p, &len, &p) != 0 ||
        parse_hex(p, &target, &p) != 0) {
        g_last_rc = -22;
        return;
    }
    if (!oal_pcie_devca_to_hostva) {
        g_last_rc = -38;
        return;
    }
    if (chip > 1U || (start & 3U) != 0 || start < 0x100000U || start > 0x1d7ffcU || len == 0U || len > 0x20000U) {
        g_last_rc = -22;
        return;
    }

    end = start + len;
    if (end > 0x1d8000U || end < start) end = 0x1d8000U;

    g_scan_chip = chip;
    g_scan_start = start;
    g_scan_len = len;
    g_scan_target = target;
    g_scan_scanned = 0;
    g_scan_skipped = 0;
    g_scan_hits_cnt = 0;

    addr = start;
    while (addr < end) {
        unsigned int page_base = addr & ~0xfffU;
        unsigned int page_end = page_base + 0x1000U;
        unsigned long long va = 0;
        int ret;
        if (page_end > end) page_end = end;
        ret = oal_pcie_devca_to_hostva(chip, page_base, &va);
        if (ret == 0 && (unsigned int)va != 0) {
            unsigned int va32 = (unsigned int)va;
            unsigned int cur = addr;
            while (cur < page_end) {
                unsigned int off = cur & 0xfffU;
                unsigned int val = *(volatile unsigned int *)(va32 + off);
                g_scan_scanned += 4U;
                if (val == target && g_scan_hits_cnt < 16U) {
                    g_scan_hits[g_scan_hits_cnt++] = cur;
                    printk("[HI1152_RF_TUNER] scan_sram hit chip=%u dev=0x%x val=0x%08x\n", chip, cur, val);
                }
                cur += 4U;
            }
        } else {
            g_scan_skipped += (page_end - addr);
        }
        addr = page_end;
    }
    g_last_rc = 0;
    printk("[HI1152_RF_TUNER] scan_sram done chip=%u [0x%x..0x%x) target=0x%08x hits=%u scanned=%u skipped=%u\n",
           chip, start, end, target, g_scan_hits_cnt, g_scan_scanned, g_scan_skipped);
}

static void handle_read_sram(const char *args) {
    unsigned int chip = 0, addr = 0, nwords = 0, i;
    const char *p = args;

    g_last_cmd = 3;
    if (parse_dec(p, &chip, &p) != 0 ||
        parse_hex(p, &addr, &p) != 0 ||
        parse_dec(p, &nwords, &p) != 0) {
        g_last_rc = -22;
        return;
    }
    if (!oal_pcie_devca_to_hostva) {
        g_last_rc = -38;
        return;
    }
    if (chip > 1U || (addr & 3U) != 0 || addr < 0x100000U || addr > 0x1d7ffcU || nwords == 0U || nwords > 16U) {
        g_last_rc = -22;
        return;
    }

    g_read_chip = chip;
    g_read_addr = addr;
    g_read_nwords = nwords;

    for (i = 0; i < nwords; i++) {
        unsigned long long va = 0;
        unsigned int cur = addr + (i << 2);
        if (cur > 0x1d7ffcU) {
            g_read_rets[i] = -34;
            g_read_vals[i] = 0xdeadbeefU;
            continue;
        }
        g_read_rets[i] = oal_pcie_devca_to_hostva(chip, cur, &va);
        if (g_read_rets[i] == 0 && (unsigned int)va != 0) {
            g_read_vals[i] = *(volatile unsigned int *)(unsigned int)va;
            printk("[HI1152_RF_TUNER] read_sram chip=%u 0x%x = 0x%08x\n", chip, cur, g_read_vals[i]);
        } else {
            g_read_vals[i] = 0xdeadbeefU;
        }
    }
    g_last_rc = 0;
}

static void handle_write_sram(const char *args) {
    unsigned int chip = 0, addr = 0, val = 0;
    const char *p = args;
    unsigned long long va = 0;
    int ret;
    unsigned int rb = 0;

    g_last_cmd = 4;
    if (parse_dec(p, &chip, &p) != 0 ||
        parse_hex(p, &addr, &p) != 0 ||
        parse_hex(p, &val, &p) != 0) {
        g_last_rc = -22;
        return;
    }
    if (!oal_pcie_devca_to_hostva) {
        g_last_rc = -38;
        return;
    }
    if (chip > 1U || (addr & 3U) != 0 || addr < 0x100000U || addr > 0x1d7ffcU) {
        g_last_rc = -22;
        return;
    }

    ret = oal_pcie_devca_to_hostva(chip, addr, &va);
    if (ret == 0 && (unsigned int)va != 0) {
        volatile unsigned int *ptr = (volatile unsigned int *)(unsigned int)va;
        *ptr = val;
        __asm__ volatile("dsb sy" ::: "memory");
        rb = *ptr;
        g_last_new_val = val;
        g_last_c0_rb = rb;
        g_last_rc = 0;
        printk("[HI1152_RF_TUNER] write_sram chip=%u 0x%x <= 0x%08x (rb=0x%08x)\n", chip, addr, val, rb);
    } else {
        g_last_rc = ret ? ret : -14;
    }
}

static ssize_t tuner_write(struct file *file, const char *buf, size_t count, loff_t *pos) {
    char kbuf[96];
    size_t i;
    size_t len = count < 95U ? count : 95U;
    const char *rest = (void *)0;
    (void)file;
    (void)pos;

    for (i = 0; i < sizeof(kbuf); i++) {
        ((volatile unsigned char *)kbuf)[i] = 0;
    }
    if (arm_copy_from_user(kbuf, buf, len)) {
        return -14;
    }
    kbuf[len] = '\0';

    while (len > 0U && (kbuf[len - 1U] == '\n' || kbuf[len - 1U] == '\r' || kbuf[len - 1U] == ' ' || kbuf[len - 1U] == '\t')) {
        kbuf[len - 1U] = '\0';
        len--;
    }

    if (starts_with_word(kbuf, "set_max", &rest)) {
        handle_set_max(rest);
    } else if (starts_with_word(kbuf, "scan_sram", &rest)) {
        handle_scan_sram(rest);
    } else if (starts_with_word(kbuf, "read_sram", &rest)) {
        handle_read_sram(rest);
    } else if (starts_with_word(kbuf, "write_sram", &rest)) {
        handle_write_sram(rest);
    } else {
        g_last_rc = -22;
    }

    return (ssize_t)count;
}

static const struct proc_ops tuner_fops = {
    .proc_flags = 0,
    .proc_open = tuner_open,
    .proc_read = seq_read,
    .proc_read_iter = (void *)0,
    .proc_write = tuner_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
    .proc_poll = (void *)0,
    .proc_ioctl = (void *)0,
    .proc_mmap = (void *)0,
    .proc_get_unmapped_area = (void *)0,
};

int init_module(void) {
    tuner_entry = proc_create("hi1152_rf_tuner", 0666, (void *)0, &tuner_fops);
    if (!tuner_entry) {
        printk("[HI1152_RF_TUNER] Failed to register /proc/hi1152_rf_tuner\n");
        return -12;
    }
    printk("[HI1152_RF_TUNER] Loaded cleanly.\n");
    return 0;
}

void cleanup_module(void) {
    if (tuner_entry) {
        proc_remove(tuner_entry);
        tuner_entry = (void *)0;
    }
    printk("[HI1152_RF_TUNER] Unloaded cleanly.\n");
}

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
    .name = "hi1152_rf_tuner",
    .init = init_module,
    .exit = cleanup_module,
};
