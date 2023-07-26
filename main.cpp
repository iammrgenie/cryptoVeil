#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <iostream>
#include <string>
#include <cassert>

using namespace std;
using namespace oabe;
using namespace oabe::crypto;

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
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

// Function to convert binary data to hexadecimal string
string Hex2String(const unsigned char* input, size_t length) {
    stringstream ss;
    ss << hex << setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << setw(2) << static_cast<unsigned>(input[i]);
    }
    return ss.str();
}

// Function to generate a 256 AES Key for Video Encryption
int generateKey(unsigned char *key){
    const int Key_Size = 32; 
    //unsigned char key[Key_Size];
    if(RAND_bytes(key, Key_Size) != 1) {
        cerr << "Error Generating Key." << endl;
        exit(EXIT_FAILURE);
    }
    return 0;
}

// Function to generate a random 16 byte IV
int generateIV(unsigned char *iv){
    const int ivSize = 16; 
    if(RAND_bytes(iv, ivSize) != 1) {
        cerr << "Error Generating IV." << endl;
        exit(EXIT_FAILURE);
    }
    return 0;
}

//Function to perform AES Encryption
int encryptAES(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

//Function to perform AES Decryption
int decryptAES(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

//Function to Generate ECC Key pair using EVP
EVP_PKEY* generateRSAKeyPair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        cerr << "Error creating EVP_PKEY context." << endl;
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_keygen_init(ctx) != 1) {
        cerr << "Error initializing EVP_PKEY key generation." << endl;
        EVP_PKEY_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Set the curve name (you can choose a different curve if desired)
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) != 1) {
        cerr << "Error setting RSA key size." << endl;
        EVP_PKEY_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY* rsaKeyPair = NULL;
    if (EVP_PKEY_keygen(ctx, &rsaKeyPair) != 1) {
        cerr << "Error generating RSA key pair." << endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(rsaKeyPair);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);
    return rsaKeyPair;
}

// Function to export the EVP_PKEY Private in PEM format
string exportPrivToPEM(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        cerr << "Error creating BIO." << endl;
        exit(EXIT_FAILURE);
    }

    if (PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        cerr << "Error exporting EVP_PKEY Private Key to PEM format." << endl;
        BIO_free_all(bio);
        EVP_PKEY_free(pkey);
        exit(EXIT_FAILURE);
    }

    char* buffer;
    long length = BIO_get_mem_data(bio, &buffer);
    string pemKey(buffer, length);

    BIO_free_all(bio);
    return pemKey;
}

// Function to export the EVP_PKEY Public in PEM format
string exportPubToPEM(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        cerr << "Error creating BIO." << endl;
        exit(EXIT_FAILURE);
    }

    if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
        cerr << "Error exporting EVP_PKEY Public key to PEM format." << endl;
        BIO_free_all(bio);
        EVP_PKEY_free(pkey);
        exit(EXIT_FAILURE);
    }

    char* buffer;
    long length = BIO_get_mem_data(bio, &buffer);
    string pemPublicKey(buffer, length);

    BIO_free_all(bio);
    return pemPublicKey;
}


int envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plain_len, unsigned char **encrypted_key, int *encrypted_key_len, unsigned char *iv,
	unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;
	int cipher_len;

	int len;

    *encrypted_key = new unsigned char[EVP_PKEY_size(*pub_key)];

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the envelope seal operation. This operation generates
	 * a key for the provided cipher, and then encrypts that key a number
	 * of times (one for each public key provided in the pub_key array). In
	 * this example the array size is just one. This operation also
	 * generates an IV and places it in iv. */

	if(1 != EVP_SealInit(ctx, EVP_aes_256_cbc(), encrypted_key,
		encrypted_key_len, iv, pub_key, 1))
		handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_SealUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plain_len))
		handleErrors();
	cipher_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_SealFinal(ctx, ciphertext + len, &len)) handleErrors();
	cipher_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return cipher_len;
}

int envelope_open(EVP_PKEY *priv_key, unsigned char *ciphertext, int cipher_len, unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv,
	unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;
	int plain_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. The asymmetric private key is
	 * provided and priv_key, whilst the encrypted session key is held in
	 * encrypted_key */
	if(1 != EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key,
		encrypted_key_len, iv, priv_key))
		handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_OpenUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, cipher_len))
		handleErrors();
	plain_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_OpenFinal(ctx, plaintext + len, &len)) handleErrors();
	plain_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plain_len;
}


int main (void)
{   
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    cout << "******************* CryptoVeil - CP-ABE Test Implementation ******************************\n" << endl;
    
    //Initialize the ABE Context
    InitializeOpenABE();

    //Specify the specific ABE scheme context and PKE context being used
    OpenABECryptoContext cpabe("CP-ABE");

    //Generate MSK and MPK
    string mpk, msk;

    cpabe.generateParams();                                         //Function to generate the msk and mpk
    cpabe.exportSecretParams(msk);
    cpabe.exportPublicParams(mpk);

    cout << "MSK: " << msk << endl;
    cout << "\nMPK: " << mpk << endl;

    /* A 256 bit key */
    //unsigned char key[32];
    //generateKey(key);

    /* A 128 bit IV */
    unsigned char iv[16];
    generateIV(iv);

    // Convert the mpk string unsigned char* array
    unsigned char* plaintext = new unsigned char[mpk.size() + 1]; // +1 for null terminator
    strcpy((char*)plaintext, mpk.c_str());

    int plaintext_len = strlen((const char*)plaintext);

    // ========================= RSA Key Generation ==========================================
    EVP_PKEY *rsaPair = generateRSAKeyPair();

    string KeyPrivPem = exportPrivToPEM(rsaPair);
    cout << "\nGenerated RSA Private Key: " << KeyPrivPem << endl;

    string KeyPubPem = exportPubToPEM(rsaPair);
    cout << "\nGenerated RSA Public Key: " << KeyPubPem << endl;

    unsigned char ciphertext[1024];
    unsigned char *encrypted_key;
    int encrypted_key_len;
    int cipher_len;

    cipher_len = envelope_seal(&rsaPair, plaintext, plaintext_len, &encrypted_key, &encrypted_key_len, iv, ciphertext);
    
    unsigned char decrypted_text[plaintext_len];
    int decrypted_len = envelope_open(rsaPair, ciphertext, cipher_len, encrypted_key, encrypted_key_len, iv, decrypted_text);

    decrypted_text[decrypted_len] = '\0';

    /* Output the results */
    cout << "Original MPK: " << plaintext << endl;
    cout << "\nDecrypted MPK: " << decrypted_text << endl;

    // ========================= CPABE Decryption Key Generation ==========================================
    //Generate decryption keys with different attributes
    string AlexDK, EugeneDK, HosseinDK, AntonisDK;
    cpabe.keygen("|Ghana|TAU|PhD|Exp = 4|", "Eugene");
    cpabe.keygen("|Greece|TAU|PhD|Exp = 5|", "Alex");
    cpabe.keygen("|Iran|TAU|PhD|Exp = 2|", "Hossein");
    cpabe.keygen("|Greece|TAU|Professor|Exp = 10|", "Antonis");

    cpabe.exportUserKey("Alex", AlexDK);
    cpabe.exportUserKey("Eugene", EugeneDK);
    cpabe.exportUserKey("Hossein", HosseinDK);
    cpabe.exportUserKey("Antonis", AntonisDK);


    //Generate Video Encryption Keys : 10 for now
    const int numKeys = 5;
    unsigned char video_enc_keys[numKeys][32];
    string enc_keyStrings[numKeys];
    string encrypted_vid_keys[numKeys];

    for (int i = 0; i < numKeys; i ++){
        generateKey(video_enc_keys[i]);
        //convert the key to a string for CPABE encryption
        enc_keyStrings[i] = Hex2String(video_enc_keys[i], 32);
    }

    // Print the generated keys
    cout << "\nGenerated Video Encryption Keys:" << endl;
    for (int i = 0; i < numKeys; i++) {
        cout << "Key " << i + 1 << ": " << enc_keyStrings[i] << endl;
    }

    //Encrypt the generated keys with different policies
    cpabe.encrypt("TAU and (Professor or PhD) and Exp > 4", enc_keyStrings[0], encrypted_vid_keys[0]);
    cpabe.encrypt("TAU and (Professor or PhD) and Exp > 2", enc_keyStrings[1], encrypted_vid_keys[1]);
    cpabe.encrypt("TAU and (Professor or PhD) and Exp > 8", enc_keyStrings[2], encrypted_vid_keys[2]);
    cpabe.encrypt("TAU and Professor and Exp > 8", enc_keyStrings[3], encrypted_vid_keys[3]);
    cpabe.encrypt("TAU and (Professor or PhD) and Exp > 3", enc_keyStrings[4], encrypted_vid_keys[4]);


    //Test Decryption and verify that the decryption works
    string decrypted_keys[numKeys];
    string user = "Antonis";
    for (int i = 0; i < numKeys; i ++){
        if (cpabe.decrypt(user, encrypted_vid_keys[i], decrypted_keys[i])){
            cout << "Decryption successful!" << endl;
            cout << "Decrypted Key: " << decrypted_keys[i] << "\n" << endl;
        } else {
            cout << "Decryption failed!" << endl;
            cout << "Key does not meet the policy on the Ciphertext\n" << endl;
        }
    }
    

    //assert(result && enc_keyStrings[0] == decrypted_key);

    //cout << "\nRecovered key: " << decrypted_key << endl;

    EVP_PKEY_free(rsaPair);
    EVP_cleanup();
    return 0;
}





    /* Buffer for the decrypted text */
    // unsigned char decryptedtext[plaintext_len];

    // int decryptedtext_len, ciphertext_len;

    // /* Encrypt the plaintext */
    // ciphertext_len = encryptAES(plaintext, plaintext_len, key, iv, ciphertext);

    // cout << "\nCiphertext: ";
    // for (int i = 0; i < ciphertext_len; ++i) {
    //     cout << hex << static_cast<int>(ciphertext[i]);
    // }
    // cout << endl;

    // // /* Do something useful with the ciphertext here */
    // // printf("Ciphertext is:\n");
    // // BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    // /* Decrypt the ciphertext */
    // decryptedtext_len = decryptAES(ciphertext, ciphertext_len, key, iv, decryptedtext);

    // /* Add a NULL terminator. We are expecting printable text */
    // decryptedtext[decryptedtext_len] = '\0';

    // /* Show the decrypted text */
    // printf("\nDecrypted text: %s\n", decryptedtext);