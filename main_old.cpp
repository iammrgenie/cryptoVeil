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
        std::cerr << "Error during encryption: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
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
        std::cerr << "Error during decryption: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        exit(EXIT_FAILURE);
    }

    plaintextData.resize(outSize);
    return plaintextData;
}

// Function to perform AES encryption
vector<unsigned char> encryptAES(const string& data, const vector<unsigned char>& key, const vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error creating AES context." << std::endl;
        exit(EXIT_FAILURE);
    }

    vector<unsigned char> ciphertextData(data.size() + EVP_MAX_BLOCK_LENGTH);
    int encryptedSize;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertextData.data(), &encryptedSize, reinterpret_cast<const unsigned char*>(data.c_str()), data.size()) != 1 ||
        EVP_EncryptFinal_ex(ctx, ciphertextData.data() + encryptedSize, &encryptedSize) != 1) 
        {
            cerr << "Error during AES encryption." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

    EVP_CIPHER_CTX_free(ctx);
    ciphertextData.resize(encryptedSize);
    return ciphertextData;
}


// Function to perform AES decryption
string decryptAES(const vector<unsigned char>& ciphertextData, const vector<unsigned char>& key, const vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating AES context." << std::endl;
        exit(EXIT_FAILURE);
    }

    vector<unsigned char> plaintextData(ciphertextData.size() + EVP_MAX_BLOCK_LENGTH);
    int decryptedSize;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1 ||
        EVP_DecryptUpdate(ctx, plaintextData.data(), &decryptedSize, ciphertextData.data(), ciphertextData.size()) != 1 ||
        EVP_DecryptFinal_ex(ctx, plaintextData.data() + decryptedSize, &decryptedSize) != 1) 
        {
            cerr << "Error during AES decryption: " << ERR_error_string(ERR_get_error(), nullptr) << endl;
            EVP_CIPHER_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

    EVP_CIPHER_CTX_free(ctx);
    plaintextData.push_back('\0');
    plaintextData.resize(decryptedSize);
    return string(reinterpret_cast<char*>(plaintextData.data()), plaintextData.size());
}



int main() 
{   
    //Initialize OpenSSL PKE Functions
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    RAND_poll();

    //Initialize the ABE Context
    // InitializeOpenABE();

    // cout << "\n******************* CryptoVeil - CP-ABE Test Implementation ******************************\n" << endl;

    // vector<unsigned char> key1 = generateKey();             //Generate an AES 256 key
    
    // //Print and convert key to String
    // stringstream sskey;
    // cout << "Generated Key: ";
    // for (const auto& byte : key1) {
    //     cout << hex << static_cast<int>(byte);
    //     sskey << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    // }
    // cout << endl;

    // string K1 = sskey.str();
    // //cout << "Converted Key: " << K1 << endl;

    // //Specify the specific ABE scheme context and PKE context being used
    // OpenABECryptoContext cpabe("CP-ABE");

    // string cipher1, decryptedtext;

    // //Generate MSK and MPK
    // string mpk, msk;

    // cpabe.generateParams();                                         //Function to generate the msk and mpk
    // cpabe.exportSecretParams(msk);
    // cpabe.exportPublicParams(mpk);

    // cout << "\nMSK: " << msk << endl;
    // cout << "\nMPK: " << mpk << endl;

    // //Generate decryption keys with different attributes
    // string AlexDK, EugeneDK;
    // cpabe.keygen("|attr1|attr2|attr3", "Eugene");
    // cpabe.keygen("|attr1|attr3|attr5", "Alex");
    // cpabe.exportUserKey("Alex", AlexDK);
    // cpabe.exportUserKey("Eugene", EugeneDK);


    // //Encrypt the given plaintexts with different policies
    // cpabe.encrypt("attr1 and attr3", K1, cipher1);
    // //cpabe.encrypt("attr1 and attr2 and attr3", pl2, ct2);


    // //Test Decryption and verify that the decryption works
    // bool result = cpabe.decrypt("Eugene", cipher1, decryptedtext);

    // assert(result && K1 == decryptedtext);

    // cout << "\nRecovered message: " << decryptedtext << endl;

    // vector<unsigned char> key2 = hexString2Vector(decryptedtext);
    
    // cout << "Converted Decrypted Key: ";
    // for (const auto& byte : key2) {
    //     cout << hex << static_cast<int>(byte);
    // }
    // cout << endl;

    // =========================================================================================================== //
    // string P_mpk;
    // vector<unsigned char> e_key = generateKey(); 
    // vector<unsigned char> e_iv = generateIV(); 

    // cout << "\nGenerated AES Key: ";
    // for (const auto& byte : e_key) {
    //     cout << hex << static_cast<int>(byte);
    // }
    // cout << endl;

    // cout << "\nGenerated IV Key: ";
    // for (const auto& byte : e_iv) {
    //     cout << hex << static_cast<int>(byte);
    // }
    // cout << endl;

    // // RSA* rsaKeyPair = genRSAKeyPair();

    // // //Export the public and secret keys
    // // RSA* publicKey = RSAPublicKey_dup(rsaKeyPair);
    // // RSA* privateKey = RSAPrivateKey_dup(rsaKeyPair);
    // // RSA_free(rsaKeyPair);

    // // string dummydata = "AAAAFqpvyex4uI/Jz93zZKIiim+ON4ptcGsAAAHToQFBsgEEtLIBABNcmBxwStTXmkT6X5ZMFvf75JL7gZ6KydWSB+qwm5MQGATpxHI3307GNQavGcucU4YQe552r3GX6PE+IdMzT58EMLPvRopDkLcwVK7MyWbgM35mWS6BzdgZu0VvNwckMiBeogyHls62ZyKAA0J3+8cUWuAfCsn7PqDc3XXKydZBBOI0ZrWi3W3bEUzGpjEYdy9jWweueke0gPJ2fEUMd6AXn3yGxb1MPxO5eNH6/rgwPjx2O7yZD/1vp8MiUjIXTASsSm2h496hNSq1cpvsZDRHGEXCKEo06K7GUMtZ/QTNCpaSVIh7EEetUHCRc7tzLCsUlZjxGH+VuQxe93A6yGWhAmcxoSSyoSEDDFk6faIa19n1xieNCmrfs2XQLkI7PKY5cvVMMxxC6amhA2cxYaEksqEhAgJ+SuRytsZF2dxxH0Minn1MTAhvAbcJ93HKFU6cN788oQJnMqFEs6FBAwL2iIkNK4lR0AgtVSDqm0gKtA14J8DICui/m0b8V6iUDbx+smVHvmXkT3sTMao0XaCv0Pz3DZWYX5+Cye8xHh+hAWuhJR0AAAAgTuda0pGwbTjU4Qglr6xFc8XH8upr3c9ZnaQAMC0JvNs=";

    // //Encrypt the generate MPK
    // vector<unsigned char> enc_withAES_mpk = encryptAES(mpk, e_key, e_iv);

    // cout << "\nEncrypted MPK: ";
    // for (const auto& byte : enc_withAES_mpk) {
    //     cout << hex << static_cast<int>(byte);
    // }
    // cout << endl;

    // //vector<unsigned char> enc_withRSA_e_key = RSAencrypt(e_key, publicKey);

    // //Decrypt and verify the mpk
    // //vector<unsigned char> P_e_key = RSAdecrypt(enc_withRSA_e_key, privateKey);
    // P_mpk = decryptAES(enc_withAES_mpk, e_key, e_iv);
    // cout << "Decrypted MPK: " << P_mpk << endl;

    // //Shutdown and clean up
    // ShutdownOpenABE();
    // //RSA_free(publicKey);
    // //RSA_free(privateKey);

    // Generate AES-256 key and IV
    vector<unsigned char> aesKey = generateKey();
    vector<unsigned char> iv = generateIV();

    // Data to be encrypted
    string originalData = "Hello, AES-256 encryption with OpenSSL EVP!";
    cout << "Original data: " << originalData << endl;

    // Encrypt the data using AES-256 with the generated key and IV
    vector<unsigned char> encryptedData = encryptAES(originalData, aesKey, iv);

    // Decrypt the data using AES-256 with the same key and IV
    string decryptedData = decryptAES(encryptedData, aesKey, iv);
    cout << "Decrypted data: " << decryptedData << endl;

    // Clean up
    EVP_cleanup();

    return 0;
}
