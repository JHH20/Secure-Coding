#ifndef SOCK_H
#define SOCK_H

#include <sys/types.h>

class sock {
private:
    static constexpr int BUF_SIZE = 1024;
    const int fd;
    char rBuf[BUF_SIZE];
    int rLen;
public:
    sock(int fd);
    ~sock();
    ssize_t readline(char *buf);
    ssize_t write(const char *buf);
    ssize_t writef(const char *fmt, ...);
};

#endif
