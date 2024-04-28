#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>

const char* SERVER_IP = "127.0.0.1"; // The IP address of the server
const int PORT = 8080;

void receiveMessages(int clientSocket) {
    char buffer[1024];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived > 0) {
            std::cout << "Received from server: " << buffer << std::endl;
        } else {
            // Connection closed or error occurred
            std::cerr << "Connection lost or error occurred while receiving." << std::endl;
            close(clientSocket);
            break;
        }
    }
}

int main() {
    int clientSocket;
    struct sockaddr_in serverAddress;

    // Create socket
    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Set up server address
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &serverAddress.sin_addr) <= 0) {
        perror("Invalid server address or IP not supported");
        close(clientSocket);
        return -1;
    }

    // Connect to the server
    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        perror("Connection to server failed");
        close(clientSocket);
        return -1;
    }

    std::cout << "Connected to server at " << SERVER_IP << ":" << PORT << std::endl;

    // Start a thread to handle incoming messages from the server
    std::thread receiveThread(receiveMessages, clientSocket);

    // Send messages to the server
    char buffer[1024];
    while (true) {
        std::cout << "Enter message: ";
        std::cin.getline(buffer, sizeof(buffer));

        // Send message to the server
        if (send(clientSocket, buffer, strlen(buffer), 0) < 0) {
            perror("Failed to send message");
            break;
        }
    }

    // Clean up
    close(clientSocket);
    receiveThread.join();

    return 0;
}
