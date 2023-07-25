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
EVP_PKEY* generateECCKeyPair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
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
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) != 1) {
        cerr << "Error setting ECC curve." << endl;
        EVP_PKEY_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY* eccKeyPair = NULL;
    if (EVP_PKEY_keygen(ctx, &eccKeyPair) != 1) {
        cerr << "Error generating ECC key pair." << endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(eccKeyPair);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);
    return eccKeyPair;
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
    /* A 256 bit key */
    unsigned char key[32];
    generateKey(key);

    /* A 128 bit IV */
    unsigned char iv[16];
    generateIV(iv);

    /* Message to be encrypted */
    unsigned char *plaintext =
        (unsigned char *)"AAAAFqpvySbSGkot3J9UKkIH9XKAi5ZtcGsAAAHToQFBsgEEtLIBACRr0Pw4kCT7nTQtD++gbwQ87TuxM8YYYJILswYu3GBpGuX8BRn3/nDMCpJOHbIsWNgxTQ+y1ysTYhs/OmK0E2gk0H1I7uZQ+y2A52MU3z9eoxSGUtcgLtEIbDSEyi6cJRjPo7b6aeqjjU3g6mmTW0OwfZYK1B2azdHfVyaZTahEA2xoAWeQpLfuChYlF/EZyaKNPj13+3jhIPbquBcmFf0H66JCDBT+PdjWb9SNEyFuB09lQ8fJYu3HERdF6nXMRgi9JLFt/k9z6GwhpSdaf5imBi8PP5tdowdFBpXcWB3QA6Cy9GseYLUh92nhdil1OquOsQoz7bMYvVjsxUkFk72hAmcxoSSyoSECFj9I8L5xxd2jbVbgnfSkpgn7sZ6KLmBJXXz28jYsA+ehA2cxYaEksqEhAiB01KX+eXWZcF6OdgcT9hnksGmibf3KuXkXm7oNHmJjoQJnMqFEs6FBAh/gFMLuBMGCYaoVl21n1HtkVCWOrXtQQCxI4jAnBpMuBaYNONvDKagcdz0DwknbjiwjGync+QAAqVLIHB9kyRyhAWuhJR0AAAAg3So67b2U9pXHWFFNh/qki69/ms/eJdmToQajMKWseSk";


    cout << "Size of plaintext = " << strlen ((char *)plaintext) << endl;

    unsigned char ciphertext[1024];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[strlen ((char *)plaintext)];

    int decryptedtext_len, ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = encryptAES(plaintext, strlen ((char *)plaintext), key, iv, ciphertext);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    /* Decrypt the ciphertext */
    decryptedtext_len = decryptAES(ciphertext, ciphertext_len, key, iv, decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("\nDecrypted text is:\n");
    printf("%s\n", decryptedtext);

    EVP_PKEY *eccPair = generateECCKeyPair();

    string KeyPrivPem = exportPrivToPEM(eccPair);
    cout << "\nGenerate ECC Private Key: " << KeyPrivPem << endl;

    string KeyPubPem = exportPubToPEM(eccPair);
    cout << "\nGenerate ECC Public Key: " << KeyPubPem << endl;

    //envelope_seal(eccPair, )


    return 0;
}


