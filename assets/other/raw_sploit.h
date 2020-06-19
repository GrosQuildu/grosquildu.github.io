/* can be called with -nostdlib 
    just define main as _start
*/

#include <sys/syscall.h>

char* dechex(unsigned dec, char *hex, int len, int fill) {
    char mdechex[17] = "0123456789ABCDEF";
    char *hex2 = hex+len, *end = hex2;
    *hex2 = '\0';
    for (--hex2; ; hex2--) {
        *hex2 = mdechex[dec & 0xF];
        dec >>= 4;
        if (dec == 0) {
            break;
        }
    }
    // Make the string start at correct address.
    if (fill) {
        if (hex2 > hex) {
            char *c = hex, *s = hex2;
            for (c, s; s < end; s++) {
                *(c++) = *s;
            }
            // Fill with zeros at end
            for (c; c < end; c++) {
                *(c++) = '\0';
            }
        }
        return hex;
    }
    return hex2;
};

typedef __signed__ char __s8;
typedef unsigned char __u8;

typedef __signed__ short __s16;
typedef unsigned short __u16;

typedef __signed__ int __s32;
typedef unsigned int __u32;

typedef __signed__ long __s64;
typedef unsigned long __u64;

struct nlmsghdr {
    __u32       nlmsg_len;  /* Length of message including header */
    __u16       nlmsg_type; /* Message content */
    __u16       nlmsg_flags;    /* Additional flags */
    __u32       nlmsg_seq;  /* Sequence number */
    __u32       nlmsg_pid;  /* Sending process port ID */
};

struct unix_diag_req {
    __u8    sdiag_family;
    __u8    sdiag_protocol;
    __u16   pad;
    __u32   udiag_states;
    __u32   udiag_ino;
    __u32   udiag_show;
    __u32   udiag_cookie[2];
};

#define NETLINK_SOCK_DIAG   4   /* socket monitoring                */
#define AF_NETLINK  16
enum sock_type {
    SOCK_STREAM = 1,
    SOCK_DGRAM  = 2,
    SOCK_RAW    = 3,
    SOCK_RDM    = 4,
    SOCK_SEQPACKET  = 5,
    SOCK_DCCP   = 6,
    SOCK_PACKET = 10,
};

#define SYS_SOCKET  1       /* sys_socket(2)        */
#define SYS_BIND    2       /* sys_bind(2)          */
#define SYS_CONNECT 3       /* sys_connect(2)       */
#define SYS_LISTEN  4       /* sys_listen(2)        */
#define SYS_ACCEPT  5       /* sys_accept(2)        */
#define SYS_GETSOCKNAME 6       /* sys_getsockname(2)       */
#define SYS_GETPEERNAME 7       /* sys_getpeername(2)       */
#define SYS_SOCKETPAIR  8       /* sys_socketpair(2)        */
#define SYS_SEND    9       /* sys_send(2)          */
#define SYS_RECV    10      /* sys_recv(2)          */
#define SYS_SENDTO  11      /* sys_sendto(2)        */
#define SYS_RECVFROM    12      /* sys_recvfrom(2)      */
#define SYS_SHUTDOWN    13      /* sys_shutdown(2)      */
#define SYS_SETSOCKOPT  14      /* sys_setsockopt(2)        */
#define SYS_GETSOCKOPT  15      /* sys_getsockopt(2)        */
#define SYS_SENDMSG 16      /* sys_sendmsg(2)       */
#define SYS_RECVMSG 17      /* sys_recvmsg(2)       */
#define SYS_ACCEPT4 18      /* sys_accept4(2)       */
#define SYS_RECVMMSG    19      /* sys_recvmmsg(2)      */
#define SYS_SENDMMSG    20      /* sys_sendmmsg(2)      */

/* Modifiers to GET request */
#define NLM_F_ROOT  0x100   /* specify tree root    */
#define NLM_F_MATCH 0x200   /* return all matching  */
#define NLM_F_ATOMIC    0x400   /* atomic GET       */
#define NLM_F_DUMP  (NLM_F_ROOT|NLM_F_MATCH)

/* Flags values */
#define NLM_F_REQUEST       1   /* It is request message.   */
#define NLM_F_MULTI     2   /* Multipart message, terminated by NLMSG_DONE */
#define NLM_F_ACK       4   /* Reply with ack, with zero or error code */
#define NLM_F_ECHO      8   /* Echo this request        */
#define NLM_F_DUMP_INTR     16  /* Dump was inconsistent due to sequence change */

#define UDIAG_SHOW_NAME     0x00000001  /* show name (not path) */
#define UDIAG_SHOW_VFS      0x00000002  /* show VFS inode info */
#define UDIAG_SHOW_PEER     0x00000004  /* show peer socket info */
#define UDIAG_SHOW_ICONS    0x00000008  /* show pending connections */
#define UDIAG_SHOW_RQLEN    0x00000010  /* show skb receive queue len */
#define UDIAG_SHOW_MEMINFO  0x00000020  /* show memory info of a socket */

#define PROT_READ   0x1     /* page can be read */
#define PROT_WRITE  0x2     /* page can be written */
#define PROT_EXEC   0x4     /* page can be executed */
#define PROT_SEM    0x8     /* page may be used for atomic ops */
#define PROT_NONE   0x0     /* page can not be accessed */
#define PROT_GROWSDOWN  0x01000000  /* mprotect flag: extend change to start of growsdown vma */
#define PROT_GROWSUP    0x02000000  /* mprotect flag: extend change to end of growsup vma */

#define MAP_SHARED  0x01        /* Share changes */
#define MAP_PRIVATE 0x02        /* Changes are private */
#define MAP_TYPE    0x0f        /* Mask for type of mapping */
#define MAP_FIXED   0x10        /* Interpret addr exactly */
#define MAP_ANONYMOUS   0x20        /* don't use a file */

#define O_ACCMODE   00000003
#define O_RDONLY    00000000
#define O_WRONLY    00000001
#define O_RDWR      00000002

typedef int __attribute__((regparm(3))) (* _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (* _prepare_kernel_cred)(unsigned long cred);
_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;
unsigned long sock_diag_handlers, nl_table;


// https://github.com/ifduyue/musl/blob/33338ebc853d37c80f0f236cc7a92cb0acc6aace/arch/i386/syscall_arch.h
#define __SYSCALL_LL_E(x) \
((union { long long ll; long l[2]; }){ .ll = x }).l[0], \
((union { long long ll; long l[2]; }){ .ll = x }).l[1]
#define __SYSCALL_LL_O(x) __SYSCALL_LL_E((x))

#define SYSCALL_INSNS "int $0x80"
#define SYSCALL_INSNS_12 "xchg %%ebx,%%edx ; " SYSCALL_INSNS " ; xchg %%ebx,%%edx"
#define SYSCALL_INSNS_34 "xchg %%ebx,%%edi ; " SYSCALL_INSNS " ; xchg %%ebx,%%edi"

static inline long __syscall0(long n)
{
    unsigned long __ret;
    __asm__ __volatile__ (SYSCALL_INSNS : "=a"(__ret) : "a"(n) : "memory");
    return __ret;
}

static inline long __syscall1(long n, long a1)
{
    unsigned long __ret;
    __asm__ __volatile__ (SYSCALL_INSNS_12 : "=a"(__ret) : "a"(n), "d"(a1) : "memory");
    return __ret;
}

static inline long __syscall2(long n, long a1, long a2)
{
    unsigned long __ret;
    __asm__ __volatile__ (SYSCALL_INSNS_12 : "=a"(__ret) : "a"(n), "d"(a1), "c"(a2) : "memory");
    return __ret;
}

static inline long __syscall3(long n, long a1, long a2, long a3)
{
    unsigned long __ret;
#if !defined(__PIC__) || !defined(BROKEN_EBX_ASM)
    __asm__ __volatile__ (SYSCALL_INSNS : "=a"(__ret) : "a"(n), "b"(a1), "c"(a2), "d"(a3) : "memory");
#else
    __asm__ __volatile__ (SYSCALL_INSNS_34 : "=a"(__ret) : "a"(n), "D"(a1), "c"(a2), "d"(a3) : "memory");
#endif
    return __ret;
}

static inline long __syscall4(long n, long a1, long a2, long a3, long a4)
{
    unsigned long __ret;
#if !defined(__PIC__) || !defined(BROKEN_EBX_ASM)
    __asm__ __volatile__ (SYSCALL_INSNS : "=a"(__ret) : "a"(n), "b"(a1), "c"(a2), "d"(a3), "S"(a4) : "memory");
#else
    __asm__ __volatile__ (SYSCALL_INSNS_34 : "=a"(__ret) : "a"(n), "D"(a1), "c"(a2), "d"(a3), "S"(a4) : "memory");
#endif
    return __ret;
}

static inline long __syscall5(long n, long a1, long a2, long a3, long a4, long a5)
{
    unsigned long __ret;
#if !defined(__PIC__) || !defined(BROKEN_EBX_ASM)
    __asm__ __volatile__ (SYSCALL_INSNS
        : "=a"(__ret) : "a"(n), "b"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5) : "memory");
#else
    __asm__ __volatile__ ("pushl %2 ; push %%ebx ; mov 4(%%esp),%%ebx ; " SYSCALL_INSNS " ; pop %%ebx ; add $4,%%esp"
        : "=a"(__ret) : "a"(n), "g"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5) : "memory");
#endif
    return __ret;
}

static inline long __syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
    unsigned long __ret;
#if !defined(__PIC__) || !defined(BROKEN_EBX_ASM)
    __asm__ __volatile__ ("pushl %7 ; push %%ebp ; mov 4(%%esp),%%ebp ; " SYSCALL_INSNS " ; pop %%ebp ; add $4,%%esp"
        : "=a"(__ret) : "a"(n), "b"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5), "g"(a6) : "memory");
#else
    unsigned long a1a6[2] = { a1, a6 };
    __asm__ __volatile__ ("pushl %1 ; push %%ebx ; push %%ebp ; mov 8(%%esp),%%ebx ; mov 4(%%ebx),%%ebp ; mov (%%ebx),%%ebx ; " SYSCALL_INSNS " ; pop %%ebp ; pop %%ebx ; add $4,%%esp"
        : "=a"(__ret) : "g"(&a1a6), "a"(n), "c"(a2), "d"(a3), "S"(a4), "D"(a5) : "memory");
#endif
    return __ret;
}

int write(int fd, const void *buf, int count) {
    return __syscall3(4, fd, (long)buf, count);
}

void exit(int status) {
    __syscall1(1, status);
}

void *mmap(void *addr, int length, int prot, int flags,
                  int fd, int offset) {
    struct mmap_arg_struct {
         unsigned long addr;
         unsigned long len;
         unsigned long prot;
         unsigned long flags;
         unsigned long fd;
         unsigned long offset;
    };
    struct mmap_arg_struct args = {(unsigned long)addr, length, prot, flags, fd, offset};
    return (void*)__syscall1(SYS_mmap, (long)&args);
    // return (void*)__syscall6(SYS_mmap, (unsigned long)addr, length, prot, flags, fd, offset);
}

int socket(int domain, int type, int protocol) {
    // on i386 socket is not a syscall, but need to be called
    // via socketcall
    unsigned long args[3] = { (unsigned long)(domain),
        (unsigned long)(type), (unsigned long)(protocol) };
    return __syscall2(SYS_socketcall, SYS_SOCKET, (long)&args);
}

int close(int fd) {
    return __syscall1(SYS_close, fd);
}

int open(const char *pathname, int flags) {
    return __syscall2(SYS_open, (long)pathname, flags);
}

int read(int fd, void *buf, int count) {
    return __syscall3(SYS_read, fd, (long)buf, count);
}

void *memset(void *s, int c, int n) {
    char *sc = s;
    for (int i = 0; i < n; ++i) {
        sc[i] = (char)c;
    }
}

void *memset4(int *s, int c, int n) {
    for (int i = 0; i < n; ++i) {
        s[i] = c;
    }
}

int execve(const char *filename, char *const argv[], char *const envp[]) {
    return __syscall3(SYS_execve, (long)filename, (long)argv, (long)envp);
}

int getuid() {
    return __syscall0(SYS_getuid);
}

void *memcpy(void *dest, const void *src, int n) {
    char *destc = dest;
    const char *srcc = src;
    for (int i = 0; i < n; ++i) {
        destc[i] = srcc[i];
    }
}

char *strcpy(char *dest, const char *src) {
    while (*src) {
        *(dest++) = *(src++);
    }
    return dest;
}

int strlen(const char *s) {
    const char *s2 = s;
    while(*(s2++)) {};
    return s2 - s;
}