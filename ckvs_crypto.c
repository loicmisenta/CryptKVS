// ckvs_crypto

#include "ckvs.h"
#include "ckvs_crypto.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <string.h>
#include <assert.h>

#define AUTH_MESSAGE "Auth Key"
#define C1_MESSAGE   "Master Key Encryption"

//Compute the HMAC of a stretched key
int compute_HMAC(ckvs_memrecord_t *mr, const char* message, unsigned char *sha){
    unsigned int md_len_auth = 0;
    unsigned char * result_auth = HMAC(EVP_sha256(), mr->stretched_key.sha, SHA256_DIGEST_LENGTH, (const unsigned char*) message, strlen(message), sha, &md_len_auth);
    if(result_auth == NULL || md_len_auth != SHA256_DIGEST_LENGTH){
        return ERR_INVALID_COMMAND;
    }
    return ERR_NONE;
}

int ckvs_client_encrypt_pwd(ckvs_memrecord_t *mr, const char *key, const char *pwd){


    M_REQUIRE_NON_NULL(mr);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);
    if (strnlen(key, CKVS_MAXKEYLEN) > EVP_MAX_KEY_LENGTH || strnlen(key, CKVS_MAXKEYLEN) == 0) {
        return ERR_INVALID_ARGUMENT;
    }

    memset(mr, 0, sizeof(ckvs_memrecord_t));

    char* stretched_key = calloc(strlen(key)+ strlen(pwd) + 1 + 1, sizeof(char)); //second +1 is for the null terminate of the string
    if (stretched_key == NULL){
        return ERR_OUT_OF_MEMORY;
    }
    strncat(stretched_key, key, CKVS_MAXKEYLEN);
    strcat(stretched_key, "|");
    strncat(stretched_key, pwd, strlen(pwd));


    SHA256((const unsigned char *) stretched_key, strlen(stretched_key), mr->stretched_key.sha);

    int err = compute_HMAC(mr, AUTH_MESSAGE, mr->auth_key.sha);
    if (err != ERR_NONE){
        free(stretched_key);
        stretched_key = NULL;
        return err;
    }
    err = compute_HMAC(mr, C1_MESSAGE, mr->c1.sha);
    if (err != ERR_NONE){
        free(stretched_key);
        stretched_key = NULL;
        return err;
    }

    free(stretched_key);
    stretched_key = NULL;
    return ERR_NONE;
}


int ckvs_client_crypt_value(const struct ckvs_memrecord *mr, const int do_encrypt,
                            const unsigned char *inbuf, size_t inbuflen,
                            unsigned char *outbuf, size_t *outbuflen )
{
    /* ======================================
     * Implementation adapted from the web:
     *     https://man.openbsd.org/EVP_EncryptInit.3
     * Man page: EVP_EncryptInit
     * Reference:
     *    https://www.coder.work/article/6383682
     * ======================================
     */

    // constant IV -- ok given the entropy in c2
    unsigned char iv[16];
    bzero(iv, 16);

    // Don't set key or IV right away; we want to check lengths
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL, do_encrypt);

    assert(EVP_CIPHER_CTX_key_length(ctx) == 32);
    assert(EVP_CIPHER_CTX_iv_length(ctx)  == 16);

    // Now we can set key and IV
    const unsigned char* const key = (const unsigned char*) mr->master_key.sha;
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    int outlen = 0;
    if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, (int) inbuflen)) {
        // Error
        EVP_CIPHER_CTX_free(ctx);
        return ERR_INVALID_ARGUMENT;
    }

    int tmplen = 0;
    if (!EVP_CipherFinal_ex(ctx, outbuf+outlen, &tmplen)) {
        // Error
        debug_printf("crypt inbuflen %ld outlen %d tmplen %d", inbuflen, outlen, tmplen);
        EVP_CIPHER_CTX_free(ctx);
        return ERR_INVALID_ARGUMENT;
    }

    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);

    *outbuflen = (size_t) outlen;

    return ERR_NONE;
}

int ckvs_client_compute_masterkey(struct ckvs_memrecord *mr, const struct ckvs_sha *c2){
    M_REQUIRE_NON_NULL(mr);
    M_REQUIRE_NON_NULL(c2);
    unsigned int size_ok = 0;
    unsigned char * result_auth = HMAC(EVP_sha256(), &mr->c1, SHA256_DIGEST_LENGTH, c2->sha, SHA256_DIGEST_LENGTH, mr->master_key.sha, &size_ok);
    if(result_auth == NULL || size_ok != SHA256_DIGEST_LENGTH){
        return ERR_INVALID_COMMAND;
    }
    return ERR_NONE;
}
