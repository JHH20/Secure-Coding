#include <iostream>
#include <string>
#include <limits>

#include "account.h"

int main() {
    // Set floating point format precision
    std::cout.precision(std::numeric_limits<double>::max_digits10);

    Account alice(std::string("Alice"), 12345678912345678);
    Account bob(std::string("Bob"), 0);

    while (true) {
        std::cout << "Alice is donating money to Bob!\n"
            << "Alice owns $" << alice.balance() << '\n'
            << "Bob owns $" << bob.balance() << std::endl;

        std::cout << "How much should Alice give Bob? (0 to quit)\n$ " << std::flush;
        double transfer = 0;    // Set to 0 to clear previous iteration's value
        std::cin >> transfer;
        std::cin.clear();
        std::cin.ignore(10000, '\n');
        std::cout << std::endl;

        if (transfer == 0) break;
        alice.pay(bob, transfer);
    }
}
