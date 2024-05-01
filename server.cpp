#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <vector>
#include <algorithm>
#include <cmath>
#include <random>
#include <sstream>
#include "diffieHellman.cpp"

const int PORT = 8001;

struct ClientInfo {
    int socket;
    int publicKey;
    int modulus;
    int dhClientPublic;
    int dhServerPrivate;
};

std::vector<ClientInfo> clients;

int serverPublicKey, serverPrivateKey, serverModulus;

bool isPrime(int n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    for (int i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return false;
    }
    return true;
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

int gcd(int a, int b) {
    if (b == 0) return a;
    return gcd(b, a % b);
}

int modInverse(int a, int m) {
    a = a % m;
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1) return x;
    }
    return -1;
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

void generateKeys(int p, int q, int &n, int &e, int &d) {
    n = p * q;
    int phi = (p - 1) * (q - 1);

    for (e = 2; e < phi; e++) {
        if (gcd(e, phi) == 1)
            break;
    }

    d = modInverse(e, phi);
}

bool sendPublicKey(int clientSocket, int publicKey, int modulus) {
    std::string keyMessage = std::to_string(publicKey) + "," + std::to_string(modulus);
    if (send(clientSocket, keyMessage.c_str(), keyMessage.length(), 0) < 0) {
        std::cerr << "Error sending public key to client." << std::endl;
        return false;
    }
    return true;
}

bool sendDHPandG(int clientSocket, int pVal, int gVal) {
std::string keyMessage = std::to_string(pVal) + "," + std::to_string(gVal);
    if (send(clientSocket, keyMessage.c_str(), keyMessage.length(), 0) < 0) {
        std::cerr << "Error sending DH parameters to client." << std::endl;
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


bool receivePublicKey(int clientSocket, int& publicKey, int& modulus) {
    char buffer[1024];
    int valread = read(clientSocket, buffer, 1024);
    if (valread <= 0) {
        std::cerr << "Error receiving public key from client." << std::endl;
        return false;
    }

    std::string keyMessage(buffer);
    size_t delimiterPos = keyMessage.find(",");
    if (delimiterPos == std::string::npos) {
        std::cerr << "Invalid format for public key message." << std::endl;
        return false;
    }

    publicKey = std::stoi(keyMessage.substr(0, delimiterPos));
    modulus = std::stoi(keyMessage.substr(delimiterPos + 1));

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

std::string rsaEncrypt(const std::string& message, int publicKey, int modulus) {
    std::string encryptedMessage;
    for (char c : message) {
        int m = static_cast<int>(c);
        int encrypted = modPow(m, publicKey, modulus);
        encryptedMessage += std::to_string(encrypted) + " ";
    }
    return encryptedMessage;
}

void handleClient(int clientSocket) {
    // RSA exchange 
    int clientPublicKey, clientModulus;

    std::cout << "sent server rsa key: " << serverPublicKey << " and Mod: " << serverModulus << std::endl;

    if (!receivePublicKey(clientSocket, clientPublicKey, clientModulus)) {
        close(clientSocket);
        return;
    }
    
    std::cout << "Received public key from client: " << clientPublicKey << ", " << clientModulus << std::endl;
    

    // Diffie Hellman Exchange
    std::pair<int, int> PandG = genParameters();
    auto [pVal,gVal] = PandG;
    int serverDHPrivate = genPrivate(pVal);
    std::cout << "server Private exponent: " << serverDHPrivate << std::endl;
    int serverDHPublic = computePublic(gVal, pVal, serverDHPrivate);
    int clientDHpublic;

    if(!sendDHPandG(clientSocket, pVal, gVal)) {
	close(clientSocket);
	return;
    }
    std::cout << "sent Pval: " << pVal << " and Gval: " << gVal << std::endl;
        

    if(!receiveDHPublicKey(clientSocket, clientDHpublic)) {
	close(clientSocket);
	return;
    }

    std::cout << "Received DH public from client: " << clientDHpublic << std::endl;

    if(!sendDHPublicKey(clientSocket, serverDHPublic)) {
	close(clientSocket);
	return;
    }

    std::cout << "sent DH server Public Key: " << serverDHPublic << std::endl;


    

    clients.push_back({clientSocket, clientPublicKey, clientModulus, clientDHpublic, serverDHPrivate });
    

    

    char buffer[1024];
    while (true) {
        int valread = read(clientSocket, buffer, 1024);
        if (valread <= 0) {
            std::cout << "Client disconnected." << std::endl;
            break;
        }
        buffer[valread] = '\0'; 

        std::cout << "Received encrypted message from client: " << buffer << std::endl;
        std::string decryptedMessage = rsaDecrypt(buffer, serverPrivateKey, serverModulus);
        std::cout << "Received from client: " << decryptedMessage << std::endl;

        for (const auto& otherClient : clients) {
            if (otherClient.socket != clientSocket) {
                std::string encryptedMessage = rsaEncrypt(decryptedMessage, otherClient.publicKey, otherClient.modulus);
                send(otherClient.socket, encryptedMessage.c_str(), encryptedMessage.length(), 0);
            }
        }
    }

    auto it = std::find_if(clients.begin(), clients.end(), [clientSocket](const ClientInfo& info) {
        return info.socket == clientSocket;
    });
    if (it != clients.end()) {
        clients.erase(it);
    }

    close(clientSocket);
}

int main() {
    int p = 61;
    int q = 53;
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddress, clientAddress;
    socklen_t clientAddrLen = sizeof(clientAddress);

    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation error");
        return -1;
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(PORT);

    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        perror("Binding failed");
        return -1;
    }

    if (listen(serverSocket, 3) < 0) {
        perror("Listen failed");
        return -1;
    }

    std::cout << "Server listening on port " << PORT << std::endl;

    int mod, publicKey, privateKey;
    generateKeys(p, q, serverModulus, serverPublicKey, serverPrivateKey);

    while (true) {
        if ((clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddrLen)) < 0) {
            perror("Accept failed");
            return -1;
        }

        std::thread clientThread(handleClient, clientSocket);
        clientThread.detach();

        if (!sendPublicKey(clientSocket, serverPublicKey, serverModulus)) {
            close(clientSocket);
            return -1;
        }
    }

    close(serverSocket);

    return 0;
}
