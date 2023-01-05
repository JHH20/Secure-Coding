#ifndef PROFILE_H
#define PROFILE_H

#include <string>

class Profile {
private:
    std::string username;
    std::string format;
public:
    Profile(std::string name);
    void setFormat(std::string format);
    std::string display();
};

#endif
