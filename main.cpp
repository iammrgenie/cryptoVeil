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


// Function to generate an AES Key for Video Encryption
vector<unsigned char> generateKey(int keySize){
    vector<unsigned char> key(keySize);
    if(RAND_bytes(key.data(), keySize) != 1) {
        cerr << "Error Generating Key." << endl;
        exit(EXIT_FAILURE);
    }
    return key;
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
vector<unsigned char> RSAencrypt(const std::string& msg, RSA* pKey) {
    int KeySize = RSA_size(pKey);
    vector<unsigned char> ciphertextData(KeySize);

    int outSize = RSA_public_encrypt(msg.size(), reinterpret_cast<const unsigned char*>(msg.c_str()), ciphertextData.data(), pKey, RSA_PKCS1_PADDING);

    if (outSize == -1) {
        std::cerr << "Error during encryption: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        exit(EXIT_FAILURE);
    }

    ciphertextData.resize(outSize);
    return ciphertextData;
}

// Function to compute RSA Decryption
string RSAdecrypt(const vector<unsigned char>& ciphertextData, RSA* sKey) {
    int KeySize = RSA_size(sKey);
    vector<unsigned char> plaintextData(KeySize);

    int outSize = RSA_private_decrypt(ciphertextData.size(), ciphertextData.data(), plaintextData.data(), sKey, RSA_PKCS1_PADDING);

    if (outSize == -1) {
        std::cerr << "Error during decryption: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        exit(EXIT_FAILURE);
    }

    return string(reinterpret_cast<char*>(plaintextData.data()), outSize);
}

int main() 
{   
    //Initialize OpenSSL PKE Functions
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    //Initialize the ABE Context
    InitializeOpenABE();

    cout << "\n******************* CryptoVeil - CP-ABE Test Implementation ******************************\n" << endl;

    const int Key_Size = 32;                                        //Using 32bit key size for AES 256
    vector<unsigned char> key1 = generateKey(Key_Size);             //Generate an AES256 key
    
    //Print and convert key to String
    stringstream sskey;
    cout << "Generated Key: ";
    for (const auto& byte : key1) {
        cout << hex << static_cast<int>(byte);
        sskey << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    }
    cout << endl;

    string K1 = sskey.str();
    cout << "Converted Key: " << K1 << endl;

    //Specify the specific ABE scheme context and PKE context being used
    OpenABECryptoContext cpabe("CP-ABE");

    string cipher1, decryptedtext;

    //Generate MSK and MPK
    string mpk, msk;

    cpabe.generateParams();                                         //Function to generate the msk and mpk
    cpabe.exportSecretParams(msk);
    cpabe.exportPublicParams(mpk);

    cout << "\nMSK: " << msk << endl;
    cout << "\nMPK: " << mpk << endl;

    //Generate decryption keys with different attributes
    string AlexDK, EugeneDK;
    cpabe.keygen("|attr1|attr2|attr3", "key0");
    cpabe.keygen("|attr1|attr3", "key1");
    cpabe.exportUserKey("key0", AlexDK);
    cpabe.exportUserKey("key1", EugeneDK);


    //Encrypt the given plaintexts with different policies
    cpabe.encrypt("attr1 and attr3", K1, cipher1);
    //cpabe.encrypt("attr1 and attr2 and attr3", pl2, ct2);


    //Test Decryption and verify that the decryption works
    bool result = cpabe.decrypt("key1", cipher1, decryptedtext);

    assert(result && K1 == decryptedtext);

    cout << "\nRecovered message: " << decryptedtext << endl;

    vector<unsigned char> key2 = hexString2Vector(decryptedtext);
    
    cout << "Converted Decrypted Key: ";
    for (const auto& byte : key2) {
        cout << hex << static_cast<int>(byte);
    }
    cout << endl;

    // =========================================================================================================== //
    string C_mpk, P_mpk;

    RSA* rsaKeyPair = genRSAKeyPair();

    //Export the public and secret keys
    RSA* publicKey = RSAPublicKey_dup(rsaKeyPair);
    RSA* privateKey = RSAPrivateKey_dup(rsaKeyPair);
    RSA_free(rsaKeyPair);

    string dummydata = "Hello, Testing Encryption";

    //Encrypt the generate MPK
    vector<unsigned char> c_mpk = RSAencrypt(dummydata, publicKey);

    //Decrypt and verify the mpk
    P_mpk = RSAdecrypt(c_mpk, privateKey);
    cout << "Decrypted MPK: " << P_mpk << endl;

    //Shutdown and clean up
    ShutdownOpenABE();
    RSA_free(publicKey);
    RSA_free(privateKey);
    EVP_cleanup();

    return 0;
}
