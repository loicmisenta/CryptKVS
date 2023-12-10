#include <stdbool.h>
#include <stdlib.h>
#include "ckvs_io.h"


#define VERSION 1

/**
 * @brief takes a number to check if it is a power of two
 * @param x number to evaluate
 * @return int as bool
 */
int isPowerOfTwo(uint32_t x){
    return (x != 0) && ((x & (x - 1)) == 0);
}

int ckvs_open(const char *filename, struct CKVS *ckvs){
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(ckvs);

    memset(ckvs, 0, sizeof(CKVS_t));

    ckvs->file = fopen(filename, "ra+");
    size_t nb_ok;

    if (ckvs->file == NULL){
        ckvs_close(ckvs);
        return ERR_IO;
    }


    nb_ok = fread(&ckvs->header, sizeof(ckvs->header), 1, ckvs->file);
    if (nb_ok != 1){
        ckvs_close(ckvs);
        return ERR_IO;
    }

    ckvs->entries = calloc(ckvs->header.table_size, sizeof(ckvs_entry_t));
    if(ckvs->entries == NULL){
        ckvs_close(ckvs);
        return ERR_OUT_OF_MEMORY;
    }

    int prefix_ok = strncmp(CKVS_HEADERSTRING_PREFIX, ckvs->header.header_string, strlen(CKVS_HEADERSTRING_PREFIX));

    if (!(prefix_ok == 0 && ckvs->header.version == VERSION && isPowerOfTwo(ckvs->header.table_size))){
        ckvs_close(ckvs);
        return ERR_CORRUPT_STORE;
    }

    nb_ok = fread(ckvs->entries, sizeof(ckvs_entry_t), ckvs->header.table_size, ckvs->file);
    if(nb_ok != ckvs->header.table_size){
        ckvs_close(ckvs);
        return ERR_IO;
    }
    return ERR_NONE;
}


void ckvs_close(struct CKVS *ckvs){
    if (ckvs == NULL || ckvs->file == NULL){
        debug_printf("NULL pointer error or NULL file closed");
        return;
    }
    free(ckvs->entries);
    ckvs->entries = NULL;
    fclose(ckvs->file);
    ckvs->file = NULL;
}

static uint32_t ckvs_hashkey(CKVS_t* ckvs, const char* key){
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);

    ckvs_sha_t content;
    SHA256((const unsigned char*)key, strlen(key), content.sha);
    uint32_t hash = *((uint32_t*) content.sha);
    return hash & (ckvs->header.table_size - 1);
}

int ckvs_find_entry(struct CKVS *ckvs, const char *key, const struct ckvs_sha *auth_key, struct ckvs_entry **e_out){
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(auth_key);
    M_REQUIRE_NON_NULL(e_out);

    bool hit = false;
    for (uint32_t  i = 0, index = ckvs_hashkey(ckvs, key); i < ckvs->header.table_size; ++i, index = ((index + 1) & (ckvs->header.table_size - 1))) {
        if(ckvs->entries[index].key[0] == '\0'){
            //miss
            *e_out = &ckvs->entries[index];
            return ERR_KEY_NOT_FOUND;
        }

        if (strncmp(key, ckvs->entries[index].key, CKVS_MAXKEYLEN) == 0){
            //hit
            hit = true;
            *e_out = &ckvs->entries[index];
            break;
        }
    }

    if (!hit){
        //only collisions
        return ERR_KEY_NOT_FOUND;
    }

    if (ckvs_cmp_sha(auth_key, &(*e_out)->auth_key) != 0){
        return ERR_DUPLICATE_ID;
    }
    return ERR_NONE;
}
int read_value_file_content(const char* filename, char** buffer_ptr, size_t* buffer_size){
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(buffer_ptr);
    M_REQUIRE_NON_NULL(buffer_size);

    int err;
    FILE * current_file;
    current_file = fopen(filename, "rb");
    if (current_file == NULL){
        return ERR_INVALID_FILENAME;
    }
    //place the cursor at the end to compute the size of the file
    err = fseek(current_file, 0, SEEK_END);
    if (err != ERR_NONE){
        fclose(current_file);
        return ERR_IO;
    }

    long len = ftell(current_file);
    if (len == -1L){
        fclose(current_file);
        return ERR_IO;
    }
    //set the buffer size with the size of the file
    *buffer_size = ((size_t)len) + 1;

    *buffer_ptr = calloc(*buffer_size, 1);
    if(*buffer_ptr == NULL){
        fclose(current_file);
        return ERR_OUT_OF_MEMORY;
    }
    //replace the cursor at the beginning to read
    err = fseek(current_file, 0, SEEK_SET);
    if (err != ERR_NONE){
        free(*buffer_ptr);
        fclose(current_file);
        return ERR_IO;
    }

    size_t elem_read = fread(*buffer_ptr, 1, (size_t) len, current_file);
    if (elem_read != (size_t) len){
        free(*buffer_ptr);
        *buffer_ptr = NULL;
        fclose(current_file);
        return ERR_IO;
    }
    fclose(current_file);

    return ERR_NONE;
}
static int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx){
    M_REQUIRE_NON_NULL(ckvs);

    //Place the cursor at the index position by passing out the header and the idx-th entry
    int err;
    err = fseek(ckvs->file, (long)(sizeof(ckvs_header_t) + (idx)*sizeof(ckvs_entry_t)), SEEK_SET);
    if (err != ERR_NONE){
        ckvs_close(ckvs);
        return ERR_IO;
    }
    //write the entry at the idx
    size_t len = fwrite(&ckvs->entries[idx], sizeof (ckvs_entry_t), 1, ckvs->file);
    if (len != 1){
        ckvs_close(ckvs);
        return ERR_IO;
    }
    return ERR_NONE;
}

static int ckvs_write_header_to_disk(struct CKVS *ckvs){
    M_REQUIRE_NON_NULL(ckvs);

    int err;
    err = fseek(ckvs->file, 0, SEEK_SET);
    if (err != ERR_NONE){
        ckvs_close(ckvs);
        return ERR_IO;
    }
    size_t len = fwrite(&ckvs->header, sizeof (ckvs_header_t), 1, ckvs->file);
    if (len == 0){//PAS SUR
        ckvs_close(ckvs);
        return ERR_IO;
    }
    return ERR_NONE;
}

int ckvs_write_encrypted_value(struct CKVS *ckvs, struct ckvs_entry *e, const unsigned char *buf, uint64_t buflen){
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(e);
    M_REQUIRE_NON_NULL(buf);

    int err;
    //The cursor is set at the end of the file
    err = fseek(ckvs->file, 0, SEEK_END);
    if (err != ERR_NONE){
        ckvs_close(ckvs);
        return ERR_IO;
    }
    //Compute the size of the file
    long pos = ftell(ckvs->file);
    if (pos == -1L){
        ckvs_close(ckvs);
        return ERR_IO;
    }

    //write and return the size of what we juste write
    size_t len = fwrite(buf, 1, buflen, ckvs->file);
    if(len!=buflen){
        return ERR_IO;
    }
    //set the length and the position of the new entry
    e->value_len = len;
    e->value_off = (uint64_t) pos;

    //search the entry with the key and auth_key

    //compute the index of the entry
    u_int32_t idx = (uint32_t)(e - ckvs->entries);

    err = ckvs_write_entry_to_disk(ckvs, idx);
    if (err != ERR_NONE){
        ckvs_close(ckvs);
        return err;
    }

    return ERR_NONE;
}

int ckvs_new_entry(struct CKVS *ckvs, const char *key, struct ckvs_sha *auth_key, struct ckvs_entry **e_out){

    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(auth_key);
    M_REQUIRE_NON_NULL(e_out);

    //Err if the nb of entry is bigger than the treshold entries
    if(ckvs->header.num_entries == ckvs->header.threshold_entries){
        return ERR_MAX_FILES;
    }

    //err if the key is too long
    if(strlen(key) > CKVS_MAXKEYLEN){
        return ERR_INVALID_ARGUMENT;
    }


    ckvs_entry_t entry;
    memset(&entry, 0, sizeof(ckvs_entry_t));

    //assign the key for the entry
    strncpy(entry.key, key, strlen(key));
    if(strlen(key) != CKVS_MAXKEYLEN) {
        entry.key[strlen(key)] = '\0';
    }
    memcpy(entry.auth_key.sha, auth_key->sha, SHA256_DIGEST_LENGTH);

    //err if the key already exist
    int err = ckvs_find_entry(ckvs, key, auth_key, e_out);
    if(err != ERR_KEY_NOT_FOUND){
        return ERR_DUPLICATE_ID;
    }

    //If all is good, the nb of entry is updated
    ckvs->header.num_entries += 1;



    //write entry to disk
    uint32_t idx_entry = (uint32_t)(*e_out - ckvs->entries);
//    ckvs->entries[idx_entry] = entry;
    **e_out = entry;
    err = ckvs_write_entry_to_disk(ckvs, idx_entry);
    if(err != ERR_NONE){
        return err;
    }
    err = ckvs_write_header_to_disk(ckvs);
    if(err != ERR_NONE){
        return err;
    }


    return ERR_NONE;
}

