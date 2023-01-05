#include "sock.h"

#include <stdio.h>

#include <unistd.h>
#include <algorithm>
#include <iterator>
#include <cstring>
#include <cstdarg>
#include <memory>

#include <stdexcept>
#include <errno.h>

sock::sock(int fd): fd(fd), rBuf{0}, rLen(0) {
    printf("[LOG]: Socket created for fd %d\n", fd);
}

sock::~sock() {
    close(this->fd);
    printf("[LOG]: Socket destroyed for fd %d\n", this->fd);
}

/* Read data into buf up-to and including newline */
ssize_t sock::readline(char *buf) {
    char *buffer_start = this->rBuf;
    char *buffer_end = this->rBuf + BUF_SIZE;

    ssize_t count = 0;

    while(true) {
        // Read up to rBuf capacity
        errno = 0;
        ssize_t res = read(this->fd, &this->rBuf[rLen], BUF_SIZE - rLen - 1);
        if(res <= 0) {
            throw std::system_error(errno, std::generic_category());
        } else {
            this->rBuf[rLen + res] = '\0';
        }

        // Find index of newline
        char *lf = std::find(buffer_start, buffer_end, '\n');
        if(lf != buffer_end) {
            // Copy line into *buf and shift rBuf accordingly
            ssize_t more = lf + 1 - buffer_start;
            ssize_t rem = rLen + res - more;

            memcpy(buf, this->rBuf, more);
            count += more;

            memmove(buffer_start, lf + 1, rem + 1); // Include '\0'
            this->rLen = rem;
            return count;
        } else {
            // Flush rBuf
            memcpy(buf, this->rBuf, BUF_SIZE - 1);
            count += BUF_SIZE - 1;
            buf += BUF_SIZE - 1;
            this->rLen = 0;
        }
    }
}

ssize_t sock::write(const char *buf) {
    size_t toSend = strlen(buf);
    ssize_t count = 0;
    while(count < toSend) {
        ssize_t res = ::write(this->fd, buf, strlen(buf));
        if(res == -1)
            throw std::system_error(errno, std::generic_category());

        count += res;
        buf += res;
    }

    return count;
}

ssize_t sock::writef(const char *fmt, ...) {
    char *wBuf;

    va_list args;
    va_start(args, fmt);
    ssize_t res = vasprintf(&wBuf, fmt, args);
    va_end(args);

    // sock::write can throw exception so use unique_ptr for auto free
    std::unique_ptr<char, decltype(free)*> data(wBuf, free);
    return sock::write(wBuf);
}
