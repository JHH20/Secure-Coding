#include <iostream>
#include <string>

#include "profile.h"

int main() {
    std::cout << "Enter your profile's username: " << std::flush;
    std::string username;
    getline(std::cin, username);

    Profile user(username);

    while (true) {
        std::cout << "\nEnter a format specifier:" << std::endl;
        std::string fmt;
        getline(std::cin, fmt);

        user.setFormat(fmt);
        std::cout << "Your name will be displayed as...\n"
            << user.display()
            << "\nAre you satisfied? (y/n) " << std::flush;

        std::string response;
        getline(std::cin, response);
        if(response[0] == 'y') break;
    }
}
