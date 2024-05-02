#include <cstring>
#include <vector>
#include <unistd.h>
#include <cmath>

 char* caesarEncrypt(int key, const char* plainText) {
    char* cipherText = new char[1024];

    for (int i = 0; i < 1024; i++) {
	if (std::isalpha(plainText[i])) {
	    char alphaCase; 
	    if (std::isupper(plainText[i])) {
		alphaCase = 'A';
	    }
	    else {
		alphaCase = 'a';
	    }
	    cipherText[i] = (((plainText[i] - alphaCase + key) % 26) + alphaCase);
	}
	else {
	    cipherText[i] = plainText[i];
	}
    }
    cipherText[1023] = '\0'; //no buffer overflow!
    return cipherText;
 }


 char* caesarDecrypt(int key, const char* cipherText) {
    char* plainText = new char[1024];

    for (int i = 0; i < 1024; i++) {
	if (std::isalpha(cipherText[i])) {
	    char alphaCase; 
	    if (std::isupper(cipherText[i])) {
		alphaCase = 'A';
	    }
	    else {
		alphaCase = 'a';
	    }
	    plainText[i] = (((cipherText[i] - alphaCase - key + 26) % 26) + alphaCase);
	}
	else {
	    plainText[i] = cipherText[i];
	}
    }
    plainText[1023] = '\0';
    return plainText;
 }

