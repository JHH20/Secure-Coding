#include "account.h"

#include <string>

Account::Account(std::string owner, double init): owner(owner), bal(init) {}

void Account::pay(Account &recipient, double amount) {
    this->bal -= amount;
    recipient.bal += amount;
}

double Account::balance() {return this->bal;}
