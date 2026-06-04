/* Fast /proc scanner - skips sshd processes, outputs tab-separated:
   pid \t comm \t ppid \t utime \t stime \t rss_pages */
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    DIR *d = opendir("/proc");
    if (!d) return 1;
    struct dirent *e;
    char path[64], buf[512];
    while ((e = readdir(d))) {
        char *p = e->d_name;
        if (*p < '0' || *p > '9') continue;
        int pid = atoi(p);
        if (pid <= 0) continue;

        snprintf(path, sizeof(path), "/proc/%d/stat", pid);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        int n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) continue;
        buf[n] = 0;

        char *lp = strchr(buf, '(');
        char *rp = strrchr(buf, ')');
        if (!lp || !rp || rp <= lp) continue;

        int commlen = rp - lp - 1;
        if (commlen == 4 && memcmp(lp + 1, "sshd", 4) == 0) continue;

        char *f = rp + 2;
        char *fields[24];
        int fi = 0;
        char *tok = strtok(f, " ");
        while (tok && fi < 24) {
            fields[fi++] = tok;
            tok = strtok(NULL, " ");
        }
        if (fi < 22) continue;

        printf("%d\t", pid);
        fwrite(lp + 1, 1, commlen, stdout);
        printf("\t%s\t%s\t%s\t%s\n",
               fields[1], fields[11], fields[12], fields[21]);
    }
    closedir(d);
    return 0;
}
