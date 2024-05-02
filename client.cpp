#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <cmath>
#include <random>
#include <vector>
#include <sstream>
#include "diffieHellman.cpp"
#include "CaesarCipher.cpp"

const int PORT = 8003;
const char* SERVER_ADDRESS = "127.0.0.1";

bool isPrime(int num) {
    if (num <= 1)
        return false;
    if (num == 2)
        return true;
    if (num % 2 == 0)
        return false;
    for (int i = 3; i <= sqrt(num); i += 2) {
        if (num % i == 0)
            return false;
    }
    return true;
}

int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

int modInverse(int a, int m) {
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1) {
            return x;
        }
    }
    return -1;
}

void generateKeys(int p, int q, int &n, int &e, int &d) {
    n = p * q;
    int phi = (p - 1) * (q - 1);

    for (e = 2; e < phi; e++) {
        if (gcd(e, phi) == 1)
            break;
    }

    d = modInverse(e, phi);
}

int modPow(int base, int exponent, int modulus) {
    int result = 1;
    base = base % modulus;
    while (exponent > 0) {
        if (exponent % 2 == 1)
            result = (result * base) % modulus;
        exponent = exponent >> 1;
        base = (base * base) % modulus;
    }
    return result;
}

int modExp(int base, int exponent, int modulus) {
    if (modulus == 1)
        return 0;
    int result = 1;
    base = base % modulus;
    while (exponent > 0) {
        if (exponent % 2 == 1)
            result = (result * base) % modulus;
        exponent = exponent >> 1;
        base = (base * base) % modulus;
    }
    return result;
}

 int generateRandomPrime(int min, int max) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(min, max);
    int candidate = dist(gen);
    while (!isPrime(candidate)) {
        candidate = dist(gen);
    }
    return candidate;
}

bool sendPublicKey(int clientSocket, int publicKey, int modulus) {
    std::string keyMessage = std::to_string(publicKey) + "," + std::to_string(modulus);
    if (send(clientSocket, keyMessage.c_str(), keyMessage.length(), 0) < 0) {
        std::cerr << "Error sending public key to server." << std::endl;
        return false;
    }
    return true;
}

bool sendDHPublicKey(int clientSocket, int publicKey) {
    std::string keyMessage = std::to_string(publicKey);
    if (send(clientSocket, keyMessage.c_str(), keyMessage.length(), 0) < 0) {
        std::cerr << "Error sending DH public key to client." << std::endl;
        return false;
    }
    return true;
}


bool receiveDHPublicKey(int clientSocket, int& publicKey) {
    char buffer[1024];
    int valread = read(clientSocket, buffer, 1024);
    if (valread <= 0) {
        std::cerr << "Error receiving public key from client." << std::endl;
        return false;
    }
    std::string keyMessage(buffer);

    publicKey = std::stoi(keyMessage);

    return true;
}


bool receivePublicKey(int clientSocket, int& ServerpublicKey, int& Servermodulus) {
    char buffer[1024];
    int valread = read(clientSocket, buffer, 1024);
    if (valread <= 0) {
        std::cerr << "Error receiving public key from server." << std::endl;
        return false;
    }

    std::string keyMessage(buffer);
    size_t delimiterPos = keyMessage.find(",");
    if (delimiterPos == std::string::npos) {
        std::cerr << "Invalid format for public key message." << std::endl;
        return false;
    }

    ServerpublicKey = std::stoi(keyMessage.substr(0, delimiterPos));
    Servermodulus = std::stoi(keyMessage.substr(delimiterPos + 1));

    return true;
}

bool receiveDHPandG(int clientSocket, int& pVal, int& gVal) {
    char buffer[1024];
    int valread = read(clientSocket, buffer, 1024);
    if (valread <= 0) {
        std::cerr << "Error receiving public key from server." << std::endl;
        return false;
    }

    std::string keyMessage(buffer);
    size_t delimiterPos = keyMessage.find(",");
    if (delimiterPos == std::string::npos) {
        std::cerr << "Invalid format for public key message." << std::endl;
        return false;
    }

    pVal = std::stoi(keyMessage.substr(0, delimiterPos));
    gVal = std::stoi(keyMessage.substr(delimiterPos + 1));

    return true;
}





std::vector<int> rsaEncrypt(const std::string &plaintext, int e, int n) {
    std::vector<int> ciphertext;
    for (char c : plaintext) {
        ciphertext.push_back(modExp(c, e, n));
    }
    return ciphertext;
}

std::string rsaDecrypt(const std::string& encryptedMessage, int privateKey, int modulus) {
    std::string decryptedMessage;
    std::stringstream iss(encryptedMessage);
    int encrypted;
    while (iss >> encrypted) {
        int decrypted = modPow(encrypted, privateKey, modulus);
        decrypted = decrypted % 256;
        decryptedMessage += static_cast<char>(decrypted);
    }
    return decryptedMessage;
}

void receiveMessages(int clientSocket, int privateKey, int modulus, int serverDHPublic, int clientDHprivate, int pVal) {
    char buffer[1024];
    while (true) {
        int valread = read(clientSocket, buffer, 1024);
        if (valread <= 0) {
            std::cout << "Server disconnected." << std::endl;
            break;
        }
        buffer[valread] = '\0';

        std::cout << "Received encrypted message from client: " << buffer << std::endl;
        std::string decryptedMessage = rsaDecrypt(buffer, privateKey, modulus);
        std::cout << "Decrypting with: " << privateKey << modulus << std::endl;
	int caesarKey = resolveKey(serverDHPublic, clientDHprivate, pVal);
	std::string plaintext = caesarDecrypt(caesarKey, decryptedMessage.c_str());
        std::cout << "Received from server: " << plaintext << std::endl;
    }
}

int main() {
    int p = generateRandomPrime(10,100);
    int q = generateRandomPrime(10,100);
    int clientSocket = 0;
    struct sockaddr_in serverAddress;

    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_ADDRESS, &serverAddress.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        return -1;
    }

    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        perror("Connection failed");
        return -1;
    }

    std::cout << "Connected to the server on port " << PORT << std::endl;

    // start RSA exchange
   
    int serverPublicKey, serverModulus;
    if (!receivePublicKey(clientSocket, serverPublicKey, serverModulus)) {
        close(clientSocket);
        return -1;
    }

    std::cout << "Received server's public key: " << serverPublicKey << ", " << serverModulus << std::endl;
    

    int mod, publicKey, privateKey, pVal, gVal, serverDHPublic, clientDHpublic, clientDHprivate;
    generateKeys(p, q, mod, publicKey, privateKey);

    if (!sendPublicKey(clientSocket, publicKey, mod)) {
        close(clientSocket);
        return -1; 
    }
    std::cout << "sent publickey: " << publicKey << " mod: " << mod << std::endl;
    

    // Start Diffie Hellman Exchange

    if(!receiveDHPandG(clientSocket, pVal, gVal)) {
	close(clientSocket);
	return -1;
    }

    std::cout << "Received DH P: " << pVal << " and DH G: " << gVal << " from the server" << std::endl;

    clientDHprivate = genPrivate(pVal);
    std::cout << "client Private exponent: " << clientDHprivate << std::endl;
    
    clientDHpublic = computePublic(gVal, pVal, clientDHprivate);

    if(!sendDHPublicKey(clientSocket, clientDHpublic)) {
	close(clientSocket);
	return -1;
    }

    std::cout<< " Sent DH public key: " << clientDHpublic << std::endl;

    if(!receiveDHPublicKey(clientSocket, serverDHPublic)) {
	close(clientSocket);
	return -1 ;
    }

    std::cout << "Received DH public key from Server: " << serverDHPublic << std::endl;

    std::thread receiveThread(receiveMessages, clientSocket, privateKey, mod, serverDHPublic, clientDHprivate, pVal);
    receiveThread.detach();
    // sending 
    while (true) {
        std::string plaintext;
        std::getline(std::cin, plaintext);
        std::stringstream ss;
	
	int caesarKey = resolveKey(serverDHPublic, clientDHprivate, pVal);
	std::string caesarCiphertext = caesarEncrypt(caesarKey, plaintext.c_str());
        std::vector<int> encrypted = rsaEncrypt(caesarCiphertext, serverPublicKey, serverModulus);
        std::cout << "Encrypted text: ";

        for (int encryptedChar : encrypted) {
            std::cout << encryptedChar << " ";
            ss << encryptedChar << " ";
        }
        std::cout << std::endl;

        std::string result = ss.str();

        if (send(clientSocket, result.c_str(), result.length(), 0) < 0) {
            std::cerr << "Error sending message to server." << std::endl;
            break;
        }

        if (plaintext == "exit") {
            break;
        }
    }

    close(clientSocket);
    std::cout << "Disconnected from the server." << std::endl;

    return 0;
}
