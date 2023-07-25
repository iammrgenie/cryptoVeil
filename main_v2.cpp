#include <iostream>
#include <string>
#include <cassert>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace std;
using namespace oabe;
using namespace oabe::crypto;


// Function to generate a 256 AES Key for Video Encryption
vector<unsigned char> generateKey(){
    const int Key_Size = 32; 
    vector<unsigned char> key(Key_Size);
    if(RAND_bytes(key.data(), Key_Size) != 1) {
        cerr << "Error Generating Key." << endl;
        exit(EXIT_FAILURE);
    }
    return key;
}

// Function to generate a random 16 byte IV
vector<unsigned char> generateIV(){
    const int ivSize = 16; 
    vector<unsigned char> iv(ivSize);
    if(RAND_bytes(iv.data(), ivSize) != 1) {
        cerr << "Error Generating IV." << endl;
        exit(EXIT_FAILURE);
    }
    return iv;
}

// Function to convert String back to Hex Vector
vector<unsigned char> hexString2Vector (const string& inputstr) {
    vector<unsigned char> res;
    
    for (size_t i = 0; i < inputstr.length(); i += 2) {
        string byteString = inputstr.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(stoi(byteString, 0, 16));
        res.push_back(byte);
    }

    return res;
}

// Function to generate RSA key pair
RSA* genRSAKeyPair() {
    RSA* rsaKeyPair = RSA_new();
    BIGNUM* exponent = BN_new();

    // Initialize the exponent to 65537 (RSA_F4)
    if (BN_set_word(exponent, RSA_F4) != 1) {
        cerr << "Error setting RSA exponent." << endl;
        exit(EXIT_FAILURE);
    }

    if (RSA_generate_key_ex(rsaKeyPair, 2048, exponent, nullptr) != 1) {
        cerr << "Error generating RSA key pair." << endl;
        RSA_free(rsaKeyPair);
        BN_free(exponent);
        exit(EXIT_FAILURE);
    }

    BN_free(exponent);
    return rsaKeyPair;
}

// Function to perform RSA encryption
vector<unsigned char> RSAencrypt(const vector<unsigned char>& msg, RSA* pKey) {
    int KeySize = RSA_size(pKey);
    vector<unsigned char> ciphertextData(KeySize);

    int outSize = RSA_public_encrypt(msg.size(), msg.data(), ciphertextData.data(), pKey, RSA_PKCS1_PADDING);

    if (outSize == -1) {
        cerr << "Error during encryption: " << ERR_error_string(ERR_get_error(), nullptr) << endl;
        exit(EXIT_FAILURE);
    }

    ciphertextData.resize(outSize);
    return ciphertextData;
}

// Function to compute RSA Decryption
vector<unsigned char> RSAdecrypt(const vector<unsigned char>& ciphertextData, RSA* sKey) {
    int KeySize = RSA_size(sKey);
    vector<unsigned char> plaintextData(KeySize);

    int outSize = RSA_private_decrypt(ciphertextData.size(), ciphertextData.data(), plaintextData.data(), sKey, RSA_PKCS1_PADDING);

    if (outSize == -1) {
        cerr << "Error during decryption: " << ERR_error_string(ERR_get_error(), nullptr) << endl;
        exit(EXIT_FAILURE);
    }

    plaintextData.resize(outSize);
    return plaintextData;
}

// Function to perform AES encryption
int encryptAES(unsigned char *plaintext, int plain_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int cipher_len = 0;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        cerr << "Error during encryption: " << ERR_error_string(ERR_get_error(), nullptr) << endl;
        exit(EXIT_FAILURE);
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plain_len) != 1 ||
        EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) 
        {
            cerr << "Error during AES encryption." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
    
    cipher_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return cipher_len;
}


// Function to perform AES decryption
int decryptAES(unsigned char *ciphertext, int cipher_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int plain_len = 0;

    if(!(ctx = EVP_CIPHER_CTX_new())){
        cerr << "Error during decryption: " << ERR_error_string(ERR_get_error(), nullptr) << endl;
        exit(EXIT_FAILURE);
    }

   if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1 ||
       EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipher_len) != 1 ||
       EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) 
        {
            cerr << "Error during AES decryption: " << ERR_error_string(ERR_get_error(), nullptr) << endl;
            EVP_CIPHER_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

    plain_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plain_len;
}



int main() 
{   
    // Initialize OpenSSL PKE Functions
    //OpenSSL_add_all_algorithms();
    //ERR_load_crypto_strings();
    //RAND_poll();

    // Generate AES-256 key and IV
    // vector<unsigned char> aesKey = generateKey();
    // vector<unsigned char> iv = generateIV();

    /* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";

    /* Message to be encrypted */
    unsigned char *plaintext =
        (unsigned char *)"The quick brown fox jumps over the lazy dog";

    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len;

    ciphertext_len = encryptAES(plaintext, strlen ((char *)plaintext), key, iv, ciphertext);

      /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    /* Decrypt the ciphertext */
    decryptedtext_len = decryptAES(ciphertext, ciphertext_len, key, iv, decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);

    // Clean up
    //EVP_cleanup();

    return 0;
}
