#include <stdio.h>
#include <stdlib.h>
#include "error.h"
#include "ckvs_local.h"
#include "ckvs_utils.h"
#include "ckvs_io.h"
#include "ckvs_rpc.h"

#define init_ckvs(var_name, table_size, threshold) \
    struct CKVS var_name = { \
        .header = { CKVS_HEADERSTRING_PREFIX " v1", 1, table_size, threshold, 0 }, \
        .entries = calloc(table_size, sizeof(ckvs_entry_t)), \
        .file = NULL, \
    }

#define DUMMY_NAME "./dummy.ckvs"
int dump_db(FILE* file, const ckvs_header_t* header, const ckvs_entry_t* entries)
{
    if (fwrite(header, sizeof(ckvs_header_t), 1, file) != 1)
        return -1;
    if (fwrite(entries, sizeof(ckvs_entry_t), header->table_size, file) != header->table_size)
        return -1;
    return 0;
}

int create_file_and_dump_db(const char* filename, const ckvs_header_t* header, const ckvs_entry_t* entries)
{
    FILE* f = fopen(filename, "wb");
    if (f == NULL) return -1;

    int err = dump_db(f, header, entries);
    fclose(f);
    return err;
}

int create_file_and_dump_value(const char* filename, const void* buffer, size_t bytes)
{
    FILE* f = fopen(filename, "wb");
    if (f == NULL) return -1;

    int err = 0;
    if (fwrite(buffer, bytes, 1, f) != 1)
        err = 1;

    fclose(f);
    return err;
}


#define release_ckvs(ckvs) \
    free((ckvs).entries)

int main(void) {

    ckvs_connection_t conn;
    ckvs_rpc_init(&conn, "https://cs212.epfl.ch");
    const char get[] = "/abc";
    if(ckvs_rpc(&conn, get)== ERR_NONE){
        printf("PASS");
    } else{
        printf("FAIL");
    }

    if(conn.resp_buf != NULL){
        printf("PASS");
    } else{
        printf("FAIL");
    }
    if(strcmp(conn.resp_buf,"Error: Invalid command") == 0){
        printf("PASS");
    } else{
        printf("FAIL");
    }
    ckvs_rpc_close(&conn);


    /*
    char value_filename[] = "./value.txt";

    char buffer[] = "101 97 89 83 79 73 71 67 61 59 53 47 43 41 37 31 29 23 19 17 13 11 7 5 3 2";
    // add some padding at the end of the ckvs file
    char key[] = "avos"; // hash=63
    char pwd[] = "1234";

    init_ckvs(ckvs, 8, 1);
    ckvs_sha_t auth_key = { { // auth_key of "avos|1234"
                                    0xdb, 0xb8, 0x6a, 0xe4, 0x6f, 0x97, 0x69, 0x60, 0xf2, 0x2c, 0xdc, 0x53, 0x9b, 0x28, 0x37, 0x8f,
                                    0x37, 0x47, 0xb9, 0xbe, 0xc9, 0x2d, 0x15, 0xaf, 0x5c, 0x5e, 0xa1, 0x9f, 0x8c, 0x52, 0x9d, 0xfc
                            } };
    strcpy(ckvs.entries[7].key, key);
    memcpy(&ckvs.entries[7].auth_key, &auth_key, sizeof(ckvs_sha_t));
    ckvs.header.num_entries = 1;

    create_file_and_dump_db(DUMMY_NAME, &ckvs.header, ckvs.entries);
    create_file_and_dump_value(value_filename, buffer, strlen(buffer));

    char* argv[] = { key, pwd, value_filename, NULL };
    if(ckvs_local_set(DUMMY_NAME, 3, argv)== ERR_NONE){
        printf("-> PASS");
    }else{
        printf("-x FAIL");
    }

    release_ckvs(ckvs);
    remove(value_filename);
    remove(DUMMY_NAME);



    const char in[] = "abc";
    uint8_t expected[] = { 0x0a, 0xbc };
    uint8_t out[2] = { 0 };

    hex_decode(in, out);
    if(memcmp(expected, out, 2) == 0){
        printf("trop bien");
    }
    else{
        printf("nul...");
    }
*/

    /*
    init_ckvs(ckvs, 64, 16);
    char pwd[] = "0000";
    // value "secret!", encrypted with c2 (+ c1, master_key derived from stretched_key)
    const uint8_t encrypted[] = { 127, 43, 228, 107, 2, 150, 63, 178, 0, 157, 145, 42, 12, 89, 108, 134 };
    ckvs_entry_t expected = {
            .key = "hello",
            .auth_key = { {
                                  0x23, 0x20, 0x33, 0x80, 0x9c, 0xe6, 0x16, 0x68, 0x5a, 0x90, 0x82, 0x7e, 0x53, 0x66, 0x9f, 0x0d,
                                  0xbd, 0x99, 0x24, 0xad, 0xeb, 0x58, 0x43, 0x4d, 0xb1, 0x6f, 0xe9, 0x80, 0x0f, 0x88, 0x0a, 0x11
                          } },
            .c2 = { {
                            0xc0, 0xcd, 0x05, 0xaf, 0x7d, 0x3b, 0x32, 0x16, 0x21, 0x3b, 0x78, 0x2d, 0x7a, 0x1d, 0xc8, 0x7b,
                            0x12, 0x53, 0x03, 0xcc, 0xc6, 0x24, 0x1a, 0x0e, 0xcc, 0x97, 0xdb, 0x9f, 0x8c, 0x95, 0x48, 0x09
                    } },
            .value_off = sizeof(ckvs_header_t) + sizeof(ckvs_entry_t) * ckvs.header.table_size,
            .value_len = sizeof(encrypted)
    };
    memcpy(ckvs.entries + 44, &expected, sizeof(ckvs_entry_t));
    ckvs.header.num_entries = 1;

    // encrypted value not present at the given offset
    create_file_and_dump_db(DUMMY_NAME, &ckvs.header, ckvs.entries);

    char* argv[] = { expected.key, pwd, NULL };
    ckvs_local_get(DUMMY_NAME, 2, argv);

    release_ckvs(ckvs);
    remove(DUMMY_NAME);
     */
//    FILE* dummy = fopen(DUMMY_NAME, "w+b");
//
//    init_ckvs(ckvs, 64, 5);
//    ckvs.file = dummy;
//
//    // already existing entry
//    const size_t idx = 36;
//    const char* k1 = "pane"; // hash mod 64 = 36
//    strcpy(ckvs.entries[idx].key, k1);
//
//    const char* k2 = "poem"; // hash mod 64 = 36
//    ckvs_sha_t auth_key = { { 0x1 } };
//    ckvs_entry_t* e_out = NULL;
//
//    ckvs_new_entry(&ckvs, k2, &auth_key, &e_out);
//    ck_assert_ptr_nonnull(e_out);
//    assert_stored_entry_eq(dummy, idx + 1, e_out);
//
//    ck_assert_str_eq(e_out->key, k2);
//    ck_assert_int_eq(memcmp(&e_out->auth_key, &auth_key, sizeof(ckvs_sha_t)), 0);
//    ck_assert_int_eq(e_out->value_off, 0);
//    ck_assert_int_eq(e_out->value_len, 0);
//
//    release_ckvs(ckvs);
//    remove(DUMMY_NAME);

//    struct CKVS ckvs = {
//        .header = { CKVS_HEADERSTRING_PREFIX " v1", 1, 64, 16, 0 },
//        //.entries = //calloc(64, sizeof(ckvs_entry_t)),
//        .file = NULL,
//    };
//    memset(ckvs.entries, 0, CKVS_FIXEDSIZE_TABLE * sizeof(ckvs_entry_t));
//
//    // setup a conflicting entry
//    const size_t idx = 44;
//    const char* key = "key";
//    ckvs_sha_t auth_key = { { 0x02 } };
//    strcpy(ckvs.entries[idx].key, key);
//    memcpy(&ckvs.entries[idx].auth_key, &auth_key, sizeof(ckvs_sha_t));
//    ckvs.header.num_entries = 1;
//
//    // there's already an entry with same key (and auth_key)
//    ckvs_entry_t* e_out = NULL;
//    ckvs_new_entry(&ckvs, key, &auth_key, &e_out);




//    FILE *dummy = fopen(DUMMY_NAME, "w+b");
//
//    struct CKVS ckvs = {
//        .header = { CKVS_HEADERSTRING_PREFIX " v1", 1, 64, 16, 0 },
//        //.entries = //calloc(64, sizeof(ckvs_entry_t)),
//        .file = NULL,
//    };
//
//    memset(ckvs.entries, 0, CKVS_FIXEDSIZE_TABLE * sizeof(ckvs_entry_t));
//    const uint8_t padding[] = {0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233};
//    fwrite(padding, sizeof(padding), 1, dummy); // append some bytes after entries
//    ckvs.file = dummy;
//
//    const size_t idx = 41;
//    const uint64_t len = 32767; // 32KB
//    unsigned char *buff = malloc(len);
//    ckvs_entry_t expected = {{0}, {{0xF}}, {{0xA}}, 15, 10};
//    strcpy(expected.key, "ABCD");
//    memcpy(ckvs.entries + idx, &expected, sizeof(ckvs_entry_t));
//    ckvs.header.num_entries = 1;
//    expected.value_off = sizeof(ckvs_header_t) + ckvs.header.table_size * sizeof(ckvs_entry_t) + sizeof(padding);
//    expected.value_len = len;
//
//    ckvs_write_encrypted_value(&ckvs, ckvs.entries + idx, buff, len);
//
//// ckvs_write_encrypted_value should set value offset and length in entries array
//
//
//    free(buff);
//    fclose(dummy);
//    remove(DUMMY_NAME);

}

