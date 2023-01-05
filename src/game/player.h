#ifndef PLAYER_H
#define PLAYER_H

template <int SLOTS>
class Player {
private:
    static const int PRIZE_INT = 50;
    static int slotBids[SLOTS];

    int gems;
    int bidAmount;
    int choice;
public:

    Player(int initGems);
    void bid(int slot, int gems);
    void settleBid();

    int getGems();
    int getSlotBids();

    static void resetBids();
    static int slotPrize(int slot);
};

#include <algorithm>

template <int SLOTS>
int Player<SLOTS>::slotBids[SLOTS] = {0};

template <int SLOTS>
Player<SLOTS>::Player(int initGems): gems(initGems) {}

template <int SLOTS>
void Player<SLOTS>::bid(int slot, int gems) {
    this->gems -= gems;
    this->bidAmount = gems;
    Player<SLOTS>::slotBids[slot] += gems;
    this->choice = slot;
}

template <int SLOTS>
void Player<SLOTS>::settleBid() {
    int slotPrize = Player<SLOTS>::slotPrize(this->choice);
    int perBid = slotPrize / Player<SLOTS>::slotBids[this->choice];
    this->gems += perBid * this->bidAmount;
}

template <int SLOTS>
int Player<SLOTS>::getGems() {return this->gems;}

template <int SLOTS>
int Player<SLOTS>::getSlotBids() {return Player<SLOTS>::slotBids[this->choice];}

template <int SLOTS>
void Player<SLOTS>::resetBids() {
    std::fill(Player<SLOTS>::slotBids, Player<SLOTS>::slotBids + SLOTS, 0);
}

template <int SLOTS>
int Player<SLOTS>::slotPrize(int slot) {
    return Player<SLOTS>::PRIZE_INT * (slot + 1);
}


#endif
