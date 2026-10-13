// M0 spike PID 1. Throwaway: mounts basics, reports READY over vsock to the host
// (CID 2, port 1000) and serves a line protocol on vsock port 1024 for measurements.
//   PING            -> PONG <boottime_ns>
//   ECHO            -> connection becomes a PTY echo loop (bytes go through a pty pair)
//   ALLOC <mib>     -> allocate and touch <mib> MiB, reply OK
//   FREE            -> free it, reply OK
//   MOUNT <dev> <fstype> <dir> <opts>  -> reply OK / ERR errno
//   READALL <dir>   -> read every regular file below dir, reply bytes count
//   WRITE <path> <mib> -> write <mib> MiB of zeros, fsync, reply OK
//   HALT            -> sync and power off
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/vm_sockets.h>
#include <pty.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static uint64_t boottime_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static void say(int fd, const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (write(fd, buf, n) < 0) {}
}

static void send_ready(void) {
    for (int i = 0; i < 200; i++) {
        int s = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_vm a = {.svm_family = AF_VSOCK, .svm_cid = 2, .svm_port = 1000};
        if (connect(s, (struct sockaddr *)&a, sizeof a) == 0) {
            say(s, "READY %llu\n", (unsigned long long)boottime_ns());
            close(s);
            return;
        }
        close(s);
        usleep(5000);
    }
}

static void echo_loop(int conn) {
    int master, slave;
    if (openpty(&master, &slave, NULL, NULL, NULL) < 0) return;
    struct termios t;
    tcgetattr(slave, &t);
    cfmakeraw(&t);
    tcsetattr(slave, TCSANOW, &t);
    pid_t pid = fork();
    if (pid == 0) {
        close(master);
        close(conn);
        char b[4096];
        for (;;) {
            ssize_t n = read(slave, b, sizeof b);
            if (n <= 0) _exit(0);
            if (write(slave, b, n) < 0) _exit(0);
        }
    }
    close(slave);
    char b[4096];
    for (;;) {
        ssize_t n = read(conn, b, sizeof b);
        if (n <= 0) break;
        if (write(master, b, n) < 0) break;
        ssize_t got = 0;
        while (got < n) {
            ssize_t m = read(master, b + got, sizeof b - got);
            if (m <= 0) goto out;
            got += m;
        }
        if (write(conn, b, got) < 0) break;
    }
out:
    close(master);
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}

static uint64_t read_tree(const char *dir) {
    uint64_t total = 0;
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *e;
    static char buf[1 << 20];
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char p[4096];
        snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(p, &st) < 0) continue;
        if (S_ISDIR(st.st_mode)) {
            total += read_tree(p);
        } else if (S_ISREG(st.st_mode)) {
            int fd = open(p, O_RDONLY);
            ssize_t n;
            while ((n = read(fd, buf, sizeof buf)) > 0) total += n;
            close(fd);
        }
    }
    closedir(d);
    return total;
}

static char *alloc_p;
static size_t alloc_len;

static void serve(int conn) {
    FILE *f = fdopen(dup(conn), "r");
    char line[512];
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\n")] = 0;
        char a[128] = "", b[128] = "", c[128] = "", d[256] = "";
        sscanf(line, "%*s %127s %127s %127s %255s", a, b, c, d);
        if (!strncmp(line, "PING", 4)) {
            say(conn, "PONG %llu\n", (unsigned long long)boottime_ns());
        } else if (!strncmp(line, "ECHO", 4)) {
            fclose(f);
            say(conn, "OK\n");
            echo_loop(conn);
            return;
        } else if (!strncmp(line, "ALLOC", 5)) {
            alloc_len = (size_t)atol(a) << 20;
            alloc_p = mmap(NULL, alloc_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            for (size_t i = 0; i < alloc_len; i += 4096) alloc_p[i] = 1;
            say(conn, "OK\n");
        } else if (!strncmp(line, "FREE", 4)) {
            munmap(alloc_p, alloc_len);
            alloc_p = NULL;
            say(conn, "OK\n");
        } else if (!strncmp(line, "MOUNT", 5)) {
            mkdir(c, 0755);
            unsigned long fl = strstr(d, "ro") ? MS_RDONLY : 0;
            const char *data = (strcmp(d, "-") && strcmp(d, "ro")) ? d : NULL;
            if (mount(a, c, b, fl, data) == 0)
                say(conn, "OK\n");
            else
                say(conn, "ERR %d\n", errno);
        } else if (!strncmp(line, "READALL", 7)) {
            say(conn, "%llu\n", (unsigned long long)read_tree(a));
        } else if (!strncmp(line, "WRITE", 5)) {
            int fd = open(a, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            static char z[1 << 20];
            for (long i = 0; i < atol(b); i++) if (write(fd, z, sizeof z) < 0) break;
            fsync(fd);
            close(fd);
            say(conn, "OK\n");
        } else if (!strncmp(line, "UMOUNT", 6)) {
            say(conn, umount(a) == 0 ? "OK\n" : "ERR\n");
        } else if (!strncmp(line, "HALT", 4)) {
            sync();
            reboot(RB_POWER_OFF);
        } else {
            say(conn, "ERR unknown\n");
        }
    }
    fclose(f);
}

int main(void) {
    mount("proc", "/proc", "proc", 0, NULL);
    mount("sysfs", "/sys", "sysfs", 0, NULL);
    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
    mkdir("/dev/pts", 0755);
    mount("devpts", "/dev/pts", "devpts", 0, "ptmxmode=0666");
    mount("tmpfs", "/tmp", "tmpfs", 0, NULL);
    signal(SIGCHLD, SIG_IGN);

    int l = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_vm a = {.svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_ANY, .svm_port = 1024};
    bind(l, (struct sockaddr *)&a, sizeof a);
    listen(l, 16);
    send_ready();
    for (;;) {
        int c = accept4(l, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) continue;
        if (fork() == 0) {
            close(l);
            serve(c);
            _exit(0);
        }
        close(c);
    }
}
