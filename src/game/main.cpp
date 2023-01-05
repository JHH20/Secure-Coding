#include <vector>
#include <unordered_map>
#include <algorithm>        // std::find
#include <memory>           // std::shared_ptr
#include <cstring>

#include <chrono>
#include <thread>
#include <future>

#include <sys/socket.h>     // Unix socket
#include <netinet/in.h>     // TCP/IP related stuff

#include "player.h"
#include "sock.h"

constexpr int PORT = 25565;
constexpr int CONN_QUEUE = 5;
std::vector<std::shared_ptr<sock>> SOCK_FDS;

constexpr int INIT_GEMS = 100;
constexpr int BID_SLOTS = 5;
using GPlayer = Player<BID_SLOTS>;

#define strStartsWith(s, p) strncmp(p, s, strlen(p)) == 0

bool bid(sock* s, GPlayer* user) {
    bool success;
    char readBuf[11] = {0};     // Get integers (int up to 10 digits)
    try {
        // Respond slotPrize query
        while(true) {
            s->write("Slot?\n");
            s->readline(readBuf);
            if(strStartsWith(readBuf, "Done")) break;

            int i = atoi(readBuf);
            s->writef("%d:%d\n", i, GPlayer::slotPrize(i));
        }

        // Ask bid choice
        s->write("Slot:\n");
        s->readline(readBuf);
        int slotChoice = atoi(readBuf);

        // Ask bid amount
        s->write("Gems:\n");
        s->readline(readBuf);
        int bidAmount = atoi(readBuf);

        user->bid(slotChoice, bidAmount);
        success = true;
    } catch(std::system_error e) {
        success = false;
    }

    return success;
}

bool bidContinue(sock* s, GPlayer* user) {
    // Display balance
    // Ask if continue playing
    bool success;
    try {
        int slotBids = user->getSlotBids();
        int oldBal = user->getGems();
        user->settleBid();
        int newBal = user->getGems();
        s->writef(
            "SBid:%d\n"     // Total bids for your chosen slot
            "OBal:%d\n"     // Old balance in gems
            "NBal:%d\n"     // New balance in gems
            , slotBids, oldBal, newBal
        );

        // Protocol: y/n + newline
        char response[3] = {0};     // Space for newline
        s->readline(response);

        switch(response[0]) {
            case 'Y':
            case 'y':
                success = true; break;
            default:
                // Send error feedback before treating as false
                s->writef("ERR:'%s'\n", response);
            case 'N':
            case 'n':
                success = false; break;
        }
    } catch(std::system_error e) {
        success = false;
    }

    return success;
}

bool gameloop() {
    // socket fd : GPlayer
    std::unordered_map<std::shared_ptr<sock>, GPlayer> users;
    std::unordered_map<std::shared_ptr<sock>, std::future<bool>> jobs;

    std::vector<std::shared_ptr<sock>> disconnects;
    while(SOCK_FDS.size() > 0) {
        // recv new connections
        for(int i = users.size(); i < SOCK_FDS.size(); ++i) {
            users.emplace(SOCK_FDS[i], INIT_GEMS);
        }
        printf("New round with %d users\n", users.size());

        bool validGame = true;

        // ask for bidding
        puts("Asking for bids");
        GPlayer::resetBids();
        jobs.clear();
        for(auto &entry : users) {
            jobs[entry.first] = std::async(
                std::launch::async, bid, entry.first.get(), &entry.second
            );
        }
        for(auto &j : jobs) {
            if(!j.second.get()) {
                disconnects.push_back(j.first);
                validGame = false;
            }
        }
        if(!validGame) goto endRound;

        // ask if continue
        puts("Asking for game continuation");
        jobs.clear();
        for(auto &entry : users) {
            jobs[entry.first] = std::async(
                std::launch::async, bidContinue, entry.first.get(), &entry.second
            );
        }
        for(auto &j : jobs) {
            if(!j.second.get()) {
                disconnects.push_back(j.first);
                // round is not invalidated when asking for continuation
                // no need to modify validGame flag
            }
        }

        endRound:
        // End this round
        puts("Round cleanup");
        auto hasLeft = [&](auto e) {
            return std::find(disconnects.begin(), disconnects.end(), e) != disconnects.end();
        };
        auto SOCK_FDS_scope = SOCK_FDS.begin() + users.size();
        SOCK_FDS.erase(
            std::remove_if(SOCK_FDS.begin(), SOCK_FDS_scope, hasLeft),
            SOCK_FDS_scope
        );
        for(auto s : disconnects) {
            users.erase(s);
        }
        disconnects.clear();
    }

    return true;
}

// sleep until local clock time is today's 00:00 + hour:min
void sleepUntil(int hour, int min) {
    using clock = std::chrono::system_clock;
    auto currentTime = clock::to_time_t(clock::now());

    auto date = std::localtime(&currentTime);
    date->tm_hour = hour;
    date->tm_min = min;
    date->tm_sec = 0;

    auto wakeTime = clock::from_time_t(std::mktime(date));
    std::this_thread::sleep_until(wakeTime);
}

int main() {
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if(server < 0) {
        perror("Socket failed");
        exit(1);
    }

    struct sockaddr_in sAddr;
    int opt = 1;

    if(setsockopt(server, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(1);
    }

    sAddr.sin_family = AF_INET;
    sAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    sAddr.sin_port = htons(PORT);

    if(bind(server, (struct sockaddr*) &sAddr, sizeof(sAddr)) < 0) {
        perror("bind failed");
        exit(1);
    }

    if(listen(server, CONN_QUEUE) < 0) {
        perror("listen failed");
        exit(1);
    }

    // Logging
    printf(
        "Started game server on port %d\n"
        "Accepting up to %d connection backlogs\n"
    , PORT, CONN_QUEUE);

    // Keep server running with new game until maintenance time
    using seconds = std::chrono::seconds;
    auto keepRestart = std::async(std::launch::async, sleepUntil, 24, 0);
    std::future<bool> gameDone;
    while(keepRestart.wait_for(seconds(0)) != std::future_status::ready) {
        struct sockaddr_in cAddr;
        int addrlen = sizeof(cAddr);
        int fd = accept(server, (struct sockaddr*) &sAddr, (socklen_t*) &addrlen);
        if(fd < 0) {
            std::this_thread::sleep_for(seconds(1));
        } else {
            SOCK_FDS.push_back(std::make_shared<sock>(fd));
            printf("Accepting socket %d\n", fd);
            if(!gameDone.valid() || gameDone.wait_for(seconds(0)) == std::future_status::ready) {
                // Start new game instance since no running instance exists
                gameDone = std::async(std::launch::async, gameloop);
            }
        }
    }

    shutdown(server, SHUT_RDWR);
}
