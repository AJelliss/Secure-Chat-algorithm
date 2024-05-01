#include <vector>
#include <unistd.h>
#include <cmath>
#include <random>
#include <cstdlib>

int genPrivate(int P) {
    std::random_device rd;
    std::mt19937 gen(rd()); 
    std::uniform_int_distribution<> dis(1, P - 1); 
    return dis(gen);
}

std::pair<int, int> genParameters() {
    std::vector<std::pair<int, int>> paramPairs = {
        {23, 2}, {47, 5}, {17, 3}, {29, 2}, {31, 5}, {19, 3}, {37, 2}
    };
    srand(time(NULL));
    int position = rand() % paramPairs.size();
    return paramPairs[position];
}

int computePublic(int gVal, int pVal, int privateKey) {

    int result = 1;
    for (int i = 0; i < privateKey; ++i) {
        result = (result * gVal) % pVal;
    }


    return result; 
}

int resolveKey(int otherKey, int yourKey, int pVal) {
    
    int result = 1;
    for (int i = 0; i < yourKey; ++i) {
        result = (result * otherKey) % pVal;
    }

    return result; 
}



