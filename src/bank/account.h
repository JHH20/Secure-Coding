#ifndef ACCOUNT_H
#define ACCOUNT_H

#include <string>

class Account {
private:
    std::string owner;
    double bal;
public:
    Account(std::string owner, double init);
    void pay(Account &recipient, double amount);
    double balance();
};

#endif
