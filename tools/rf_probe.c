/*
 * rf_probe.c - Minimal zero-dependency Linux ARMv7 EABI WEXT ioctl probe
 * Queries live Hi1152 die temperature (0x8be1 subcmd 0x02b9 -> wal_ioctl_get_temp),
 * txpower param (0x8be1 subcmd 0x0071), and pwr_ref (0x8be7 subcmd 0x02ca).
 */

static long sys_write(int fd, const void *buf, unsigned long count) {
    register long r0 __asm__("r0") = fd;
    register long r1 __asm__("r1") = (long)buf;
    register long r2 __asm__("r2") = (long)count;
    register long r7 __asm__("r7") = 4; /* __NR_write */
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
    return r0;
}

static long sys_close(int fd) {
    register long r0 __asm__("r0") = fd;
    register long r7 __asm__("r7") = 6; /* __NR_close */
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7) : "memory");
    return r0;
}

static long sys_ioctl(int fd, unsigned long req, void *arg) {
    register long r0 __asm__("r0") = fd;
    register long r1 __asm__("r1") = (long)req;
    register long r2 __asm__("r2") = (long)arg;
    register long r7 __asm__("r7") = 54; /* __NR_ioctl */
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
    return r0;
}

static long sys_socket(int domain, int type, int protocol) {
    register long r0 __asm__("r0") = domain;
    register long r1 __asm__("r1") = type;
    register long r2 __asm__("r2") = protocol;
    register long r7 __asm__("r7") = 281; /* __NR_socket */
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
    return r0;
}

struct iwreq_int {
    char name[16];
    int val[4];
} __attribute__((packed));

struct iwreq_point {
    char name[16];
    void *ptr;
    unsigned short len;
    unsigned short flags;
    unsigned int pad[2];
} __attribute__((packed));

static void zero_mem(void *p, unsigned long n) {
    volatile unsigned char *b = (volatile unsigned char *)p;
    for (unsigned long i = 0; i < n; i++) {
        b[i] = 0;
    }
}

static void copy_ifname(char dst[16], const char *src) {
    for (unsigned long i = 0; i < 15 && src[i]; i++) {
        dst[i] = src[i];
    }
}

static unsigned long c_strlen(const char *s) {
    const volatile char *vs = (const volatile char *)s;
    unsigned long n = 0;
    while (vs[n]) n++;
    return n;
}

static void write_str(const char *s) {
    sys_write(1, s, c_strlen(s));
}

static void write_int(long v) {
    char buf[24];
    int i = 0;
    unsigned long uv;
    if (v < 0) {
        buf[i++] = '-';
        uv = (unsigned long)(-v);
    } else {
        uv = (unsigned long)v;
    }
    char rev[20];
    int j = 0;
    if (uv == 0) {
        rev[j++] = '0';
    } else {
        while (uv > 0) {
            rev[j++] = (char)('0' + (uv % 10));
            uv /= 10;
        }
    }
    while (j > 0) {
        buf[i++] = rev[--j];
    }
    sys_write(1, buf, (unsigned long)i);
}

static void write_hex_byte(unsigned char b) {
    static const char hex[] = "0123456789abcdef";
    char out[2];
    out[0] = hex[(b >> 4) & 0xf];
    out[1] = hex[b & 0xf];
    sys_write(1, out, 2);
}

int main_c(int argc, char **argv) {
    const char *ifname = (argc > 1 && argv[1] && argv[1][0]) ? argv[1] : "vap0";
    struct iwreq_int iwr_i;
    struct iwreq_point iwr_p;
    unsigned char buf[512];

    long fd = sys_socket(2 /* AF_INET */, 2 /* SOCK_DGRAM */, 0);
    if (fd < 0) {
        write_str("socket_err=");
        write_int(fd);
        write_str("\n");
        return 1;
    }

    /* 1. get_temp (0x8be1 subcmd 0x02b9) */
    zero_mem(&iwr_i, sizeof(iwr_i));
    copy_ifname(iwr_i.name, ifname);
    iwr_i.val[0] = 0x02b9;
    long temp_rc = sys_ioctl((int)fd, 0x8be1UL, &iwr_i);
    write_str("temp_rc=");
    write_int(temp_rc);
    write_str(" temp=");
    write_int((long)iwr_i.val[0]);

    /* 2. get_txpower (0x8be1 subcmd 0x0071) */
    zero_mem(&iwr_i, sizeof(iwr_i));
    copy_ifname(iwr_i.name, ifname);
    iwr_i.val[0] = 0x0071;
    long txp_rc = sys_ioctl((int)fd, 0x8be1UL, &iwr_i);
    write_str(" txp_rc=");
    write_int(txp_rc);
    write_str(" txp=");
    write_int((long)iwr_i.val[0]);

    /* 3. get_pwr_ref (0x8be7 subcmd 0x02ca) */
    zero_mem(buf, sizeof(buf));
    zero_mem(&iwr_p, sizeof(iwr_p));
    copy_ifname(iwr_p.name, ifname);
    iwr_p.ptr = buf;
    iwr_p.len = 500;
    iwr_p.flags = 0x02ca;
    long pref_rc = sys_ioctl((int)fd, 0x8be7UL, &iwr_p);
    write_str(" pref_rc=");
    write_int(pref_rc);
    write_str(" pref_len=");
    write_int((long)iwr_p.len);
    write_str(" pref_hex=");
    unsigned short dump_len = iwr_p.len;
    if (dump_len > 64) dump_len = 64;
    if (dump_len == 0 && pref_rc >= 0) dump_len = 16;
    for (unsigned short i = 0; i < dump_len; i++) {
        write_hex_byte(buf[i]);
    }
    write_str("\n");

    sys_close((int)fd);
    return 0;
}

__asm__(
    ".text\n"
    ".global _start\n"
    ".type _start, %function\n"
    "_start:\n"
    "    ldr r0, [sp]\n"
    "    add r1, sp, #4\n"
    "    bic sp, sp, #7\n"
    "    bl main_c\n"
    "    mov r7, #1\n"
    "    svc #0\n"
);
