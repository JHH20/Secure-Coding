#include <iostream>
#include <vector>
#include <string>

struct Coord {
    int x;
    int y;
};


int main() {
    std::vector<Coord> positions;

    std::cout << "Compute the average position on an xy plane!\n"
        << "How many points in the sample? " << std::flush;
    int n;
    std::cin >> n;
    std::cin.clear();
    std::cin.ignore(10000, '\n');
    std::cout << std::endl;

    while (n-- > 0) {
        std::cout << "Enter a coord as \"x y\" with a space in between: "
            << std::flush;
        std::string line;
        getline(std::cin, line);

        size_t delim = line.find(' ');
        int x = std::stoi(line.substr(0, delim), NULL, 0);
        int y = std::stoi(line.substr(delim + 1), NULL, 0);

        positions.push_back(Coord{x, y});
    }

    Coord avg{0, 0};
    for(int i = 0; i < positions.size(); ++i) {
        avg.x += positions[i].x;
        avg.y += positions[i].y;
    }
    avg.x /= positions.size();
    avg.y /= positions.size();

    std::cout << "\nThe average position is (" << avg.x << ", " << avg.y << ")"
        << std::endl;
}
