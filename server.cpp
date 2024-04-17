#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <thread>
#include <arpa/inet.h>
#include <mutex>
#include <sys/socket.h>
#include <netinet/in.h>
#include <algorithm>

const int PORT = 8080;
const int MAX_CONNECTIONS = 10;

std::vector<int> clientSockets;
std::mutex mtx;

void handleClient(int clientSocket) {
    char buffer[1024] = {0};
    int valread;
    while (true) {
        valread = read(clientSocket, buffer, 1024);
        if (valread <= 0) {
            break;
        }
        std::cout << "Received: " << buffer << std::endl;
        mtx.lock();
        for (int socket : clientSockets) {
            if (socket != clientSocket) {
                send(socket, buffer, strlen(buffer), 0);
            }
        }
        mtx.unlock();
        memset(buffer, 0, 1024);
    }
    close(clientSocket);
    mtx.lock();
    clientSockets.erase(std::remove(clientSockets.begin(), clientSockets.end(), clientSocket), clientSockets.end());
    mtx.unlock();
}

int main() {
    int serverSocket, clientSocket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(serverSocket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(serverSocket, MAX_CONNECTIONS) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    std::cout << "Server listening on port " << PORT << std::endl;

    while (true) {
        if ((clientSocket = accept(serverSocket, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        mtx.lock();
        clientSockets.push_back(clientSocket);
        mtx.unlock();
        std::thread(handleClient, clientSocket).detach();
    }

    return 0;
}
