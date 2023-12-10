#include "ckvs_io.h"
#include "ckvs_crypto.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include "util.h"
#include "ckvs_utils.h"

int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char* set_value);
int do_get(CKVS_t* ckvs, ckvs_entry_t* entry, ckvs_memrecord_t* ckvs_memrecord);
int do_set(CKVS_t* ckvs, ckvs_entry_t* entry, ckvs_memrecord_t* ckvs_memrecord, const char* set_value);

int ckvs_local_stats(const char* filename, int optargc, _unused char* optargv[]){
    M_REQUIRE_NON_NULL(filename);

    int err = check_arg_size(optargc, ARG_SIZE_STATS);
    if(err != ERR_NONE){
        return err;
    }

    CKVS_t ckvs;
    err =  ckvs_open(filename, &ckvs);
    if (err != ERR_NONE) return err;
    print_header(&ckvs.header);
    //for each entry print it if the size is ok

    for (uint32_t i = 0; i < ckvs.header.table_size; ++i) {

        if (strnlen(ckvs.entries[i].key, CKVS_MAXKEYLEN) != 0 ){
            print_entry(&ckvs.entries[i]);
        }

    }
    ckvs_close(&ckvs);
    return err;
}

int ckvs_local_get(const char* filename, int optargc, char* optargv[]){
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(optargv);

    int err = check_arg_size(optargc, ARG_SIZE_GET);
    if(err != ERR_NONE){
        return err;
    }
    const char* key = optargv[0];
    const char* pwd = optargv[1];

    return ckvs_local_getset(filename, key, pwd, NULL);
}

int ckvs_local_set(const char* filename, int optargc, char* optargv[]){
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(optargv);

    int err = check_arg_size(optargc, ARG_SIZE_SET);
    if(err != ERR_NONE){
        return err;
    }
    const char* key = optargv[0];
    const char* pwd = optargv[1];
    const char* valuefilename = optargv[2];

    size_t buffer_size;
    char *buffer_ptr = NULL;
    //read the content from the given file
    err = read_value_file_content(valuefilename, &buffer_ptr, &buffer_size);
    if (err != ERR_NONE){
        return err;
    }
    //set the given entry to the file that was read
    err = ckvs_local_getset(filename, key, pwd, buffer_ptr);
    free(buffer_ptr);
    buffer_ptr = NULL;
    return err;
}

int ckvs_local_new(const char* filename, int optargc, char* optargv[]){
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(optargv);

    int err = check_arg_size(optargc, ARG_SIZE_NEW);
    if(err != ERR_NONE){
        return err;
    }
    const char* key = optargv[0];
    const char* pwd = optargv[1];

    CKVS_t ckvs;
    ckvs_memrecord_t mr;
    ckvs_entry_t* entry = NULL;

    err = ckvs_open(filename, &ckvs);
    if(err != ERR_NONE){
        return err;
    }

    err = ckvs_client_encrypt_pwd(&mr, key, pwd);
    if(err != ERR_NONE){
        ckvs_close(&ckvs);
        return err;
    }


    err = ckvs_new_entry(&ckvs, key, &mr.auth_key, &entry);
    if(err != ERR_NONE){
        ckvs_close(&ckvs);
        return err;
    }

    ckvs_close(&ckvs);
    return ERR_NONE;
}

int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char* set_value){
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);

    CKVS_t ckvs;
    ckvs_memrecord_t ckvs_memrecord;
    ckvs_entry_t* entry = NULL;
    int err;

    err =  ckvs_open(filename, &ckvs);
    if (err != ERR_NONE){
        return err;
    }

    err = ckvs_client_encrypt_pwd(&ckvs_memrecord, key, pwd);
    if (err != ERR_NONE){
        ckvs_close(&ckvs);
        return err;
    }


    err = ckvs_find_entry(&ckvs, key, &ckvs_memrecord.auth_key, &entry);
    if(err != ERR_NONE){
        ckvs_close(&ckvs);
        return err;
    }


    if(set_value == NULL){
        if((entry->c2.sha[0] == '\0')&&(entry->value_len == 0)&&(entry->value_off == 0)){
            return ERR_NO_VALUE;
        }
    }
    //if we are in the set mode recompute master_key randomly
    if (set_value != NULL){
        err = RAND_bytes(entry->c2.sha, SHA256_DIGEST_LENGTH);
        if(err != 1){
            ckvs_close(&ckvs);
            return ERR_IO;
        }
    }

    //Compute the master_key from c1 and c2 that are already generated
    err = ckvs_client_compute_masterkey(&ckvs_memrecord, &entry->c2);
    if(err != ERR_NONE){
        ckvs_close(&ckvs);
        return err;
    }

    // if we are in the get case
    if (set_value == NULL){
        err = do_get(&ckvs, entry ,&ckvs_memrecord);
        if (err != ERR_NONE){
            ckvs_close(&ckvs);
            return err;
        }
    //if we are in the set case
    } else{
        err = do_set(&ckvs, entry, &ckvs_memrecord, set_value);
        if (err != ERR_NONE){
            ckvs_close(&ckvs);
            return err;
        }
    }

    ckvs_close(&ckvs);
    return err;
}

int do_get(CKVS_t* ckvs, ckvs_entry_t* entry, ckvs_memrecord_t* ckvs_memrecord){

    int err = fseek(ckvs->file, (long)entry->value_off, SEEK_SET);
    if (err != 0){
        return ERR_IO;
    }


    size_t inBufferLen = entry->value_len;
    size_t outBufferLen = 0;


    unsigned char* inBuffer = calloc(entry->value_len, sizeof(unsigned char));
    if(inBuffer == NULL){
        return ERR_OUT_OF_MEMORY;
    }
    unsigned char* outBuffer = calloc(entry->value_len + EVP_MAX_BLOCK_LENGTH, sizeof(unsigned char));
    if(outBuffer == NULL){
        return ERR_OUT_OF_MEMORY;
    }

    size_t read = fread(inBuffer, entry->value_len, 1, ckvs->file);
    if(read != 1){
        freePointers(inBuffer, outBuffer);
        return ERR_IO;
    }

    err = ckvs_client_crypt_value(ckvs_memrecord, 0, inBuffer, inBufferLen, outBuffer, &outBufferLen);
    if(err != ERR_NONE){
        freePointers(inBuffer, outBuffer);
        return err;
    }
    outBuffer[outBufferLen] = '\0';
    pps_printf("%s", outBuffer);
    freePointers(inBuffer, outBuffer);
    return ERR_NONE;
}

int do_set(CKVS_t* ckvs, ckvs_entry_t* entry, ckvs_memrecord_t* ckvs_memrecord, const char* set_value){
    size_t max_inBufferLen = strlen(set_value) + EVP_MAX_BLOCK_LENGTH;
    unsigned char* outBuffer = calloc(max_inBufferLen, 1);
    if(outBuffer == NULL){
        return ERR_OUT_OF_MEMORY;
    }

    //encrypt the given message
    int err = ckvs_client_crypt_value(ckvs_memrecord, 1, (const unsigned char*)set_value, strlen(set_value) + 1, outBuffer, &max_inBufferLen);
    if(err != ERR_NONE){
        free(outBuffer);
        outBuffer = NULL;
        return err;
    }

    err = ckvs_write_encrypted_value(ckvs, entry, outBuffer, max_inBufferLen);
    if (err != ERR_NONE){
        free(outBuffer);
        outBuffer = NULL;
        return err;
    }

    free(outBuffer);
    outBuffer = NULL;
    return ERR_NONE;
}

