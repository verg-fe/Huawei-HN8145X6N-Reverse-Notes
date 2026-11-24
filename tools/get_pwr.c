/*
 * get_pwr.c - Minimal zero-dependency Linux ARMv7 EABI WEXT ioctl probe
 * Invokes wal_ioctl_get_param_char (0x8beb) -> get_current_pwr (0x138b)
 * to query live DMAC per-MCS TX power table into kernel dmesg.
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

struct iwreq_min {
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

int main_c(int argc, char **argv) {
    const char *ifname = (argc > 1 && argv[1] && argv[1][0]) ? argv[1] : "vap0";
    char buf[512];
    struct iwreq_min iwr;

    zero_mem(buf, sizeof(buf));
    zero_mem(&iwr, sizeof(iwr));

    for (unsigned long i = 0; i < 15 && ifname[i]; i++) {
        iwr.name[i] = ifname[i];
    }
    iwr.ptr = buf;
    iwr.len = 500;
    iwr.flags = 0x138b; /* get_current_pwr (subcmd 5003) */

    long fd = sys_socket(2 /* AF_INET */, 2 /* SOCK_DGRAM */, 0);
    if (fd < 0) {
        write_str("socket_err=");
        write_int(fd);
        write_str("\n");
        return 1;
    }

    long rc = sys_ioctl((int)fd, 0x8bebUL, &iwr);
    sys_close((int)fd);

    buf[sizeof(buf) - 1] = '\0';
    write_str("rc=");
    write_int(rc);
    write_str(" len=");
    write_int((long)iwr.len);
    write_str(" buf=");
    write_str(buf);
    write_str("\n");

    return (rc < 0) ? 1 : 0;
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
