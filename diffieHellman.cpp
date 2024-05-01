#include <vector>
#include <unistd.h>
#include <cmath>

possibleG = 
possibleP =

int computePublic(int gVal, int pVal, int privateKey) {

    int power = power(gVal, privateKey);
    int result = power % pVal;

    return result; 
}

int resolveKey(int otherKey, int yourKey, int pVal) {
    
    int power = power(otherKey, yourKey);
    int result = power % pVal;

    return result; 
}






