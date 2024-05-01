#include <iostream>
#include <cmath>

using namespace std;

// Function to calculate gcd (greatest common divisor)
int gcd(int a, int b) {
    if (b == 0)
        return a;
    return gcd(b, a % b);
}

// Function to calculate modular multiplicative inverse
int modInverse(int a, int m) {
    a = a % m;
    for (int x = 1; x < m; x++)
        if ((a * x) % m == 1)
            return x;
    return 1;
}

// Function to generate prime numbers
bool isPrime(int n) {
    if (n <= 1)
        return false;
    if (n <= 3)
        return true;
    if (n % 2 == 0 || n % 3 == 0)
        return false;
    for (int i = 5; i * i <= n; i = i + 6)
        if (n % i == 0 || n % (i + 2) == 0)
            return false;
    return true;
}

int main() {
    int p, q, n, phi, e, d;

    // Step 1: Choose prime numbers p and q
    do {
        p = rand() % 100 + 1;
    } while (!isPrime(p));

    do {
        q = rand() % 100 + 1;
    } while (!isPrime(q));

    // Step 2: Calculate n and Euler's totient
    n = p * q;
    phi = (p - 1) * (q - 1);

    // Step 3: Choose public key e
    e = 65537; // Common choice for e

    // Step 4: Calculate private key d
    d = modInverse(e, phi);

    int message;
    cout << "Enter message to encrypt: ";
    cin >> message;

    // Step 5: Encryption
    int encrypted = pow(message, e);
    encrypted %= n;

    // Step 6: Decryption
    int decrypted = pow(encrypted, d);
    decrypted %= n;

    cout << "Encrypted: " << encrypted << endl;
    cout << "Decrypted: " << decrypted << endl;

    return 0;
}
