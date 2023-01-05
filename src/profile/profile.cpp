#include "profile.h"

#include <string>
#include <cstdio>

Profile::Profile(std::string name): username(name), format("%s") {}

void Profile::setFormat(std::string format) {
    this->format = format;
}

std::string Profile::display() {
    char *cstrRes = NULL;
    asprintf(&cstrRes, this->format.c_str(), this->username.c_str());
    std::string result(cstrRes);
    free(cstrRes);
    return result;
}
