#include <stdio.h>
#include <stdlib.h>
#include "ckvs.h"
#include "util.h"
#include <json-c/json.h>
#include <limits.h>

#define CKVS_Header_type "CKVS Header type"
#define CKVS_Header_version "CKVS Header version"
#define CKVS_Header_table_size "CKVS Header table_size"
#define CKVS_Header_treshold "CKVS Header threshold"
#define CKVS_Header_num_entries "CKVS Header num_entries"
#define CKVS_Key "Key"

#define Key "Key   "
#define Value "Value "
#define Auth "    Auth  "
#define C2 "    C2    "

void print_header(const struct ckvs_header* header){
    if (header == NULL){
        debug_printf("NULL pointer error");
        return;
    }
    pps_printf("%-23s: %s\n", CKVS_Header_type, header->header_string);
    pps_printf("%-23s: %u\n", CKVS_Header_version, header->version);
    pps_printf("%-23s: %u\n", CKVS_Header_table_size, header->table_size);
    pps_printf("%-23s: %u\n", CKVS_Header_treshold, header->threshold_entries);
    pps_printf("%-23s: %u\n", CKVS_Header_num_entries, header->num_entries);
}

void print_entry(const struct ckvs_entry* entry){
    if (entry == NULL){
        debug_printf("NULL pointer error");
        return;
    }
    pps_printf("    %s: "STR_LENGTH_FMT(CKVS_MAXKEYLEN)"\n", Key, entry->key);
    pps_printf("    %-5s: off %lu len %lu\n", Value, entry->value_off, entry->value_len);
    print_SHA(Auth, &entry->auth_key);
    print_SHA(C2, &entry->c2);
}

void hex_encode(const uint8_t *in, size_t len, char *buf){
    if (in == NULL || buf == NULL) {
        debug_printf("NULL pointer error");
        return;
    }
    for (size_t i = 0, j = 0; i < len; ++i, j += 2){
        sprintf(buf + j, "%02x", in[i] & 0xff);
    }
}

void SHA256_to_string(const struct ckvs_sha *sha, char *buf){
    if (sha == NULL || buf == NULL){
        debug_printf("NULL pointer error");
        return;
    }
    hex_encode(sha->sha,SHA256_DIGEST_LENGTH,buf);
}

void print_SHA(const char *prefix, const struct ckvs_sha *sha){
    if (prefix == NULL || sha == NULL){
        debug_printf("NULL pointer error");
        return;
    }
    char buffer[SHA256_PRINTED_STRLEN];
    SHA256_to_string(sha, buffer);
    pps_printf("%-5s: %s\n", prefix, buffer);
}

int ckvs_cmp_sha(const struct ckvs_sha *a, const struct ckvs_sha *b){
    return memcmp(a, b, SHA256_DIGEST_LENGTH);
}

int hex_decode(const char *input, uint8_t *output){
    if (input == NULL || output == NULL){
        return -1;
    }

    int nb_octet = 0;
    size_t start = 0;

    if(strlen(input)%2 != 0){
        char tab[3] = {'0', '0', '\0'};
        strncpy(tab+1, (input), 1);
        unsigned long first = strtoul(tab, NULL, 16);
        if(first == ULONG_MAX){
            return -1;
        }
        output[0] = (uint8_t)first;
        ++start;
        ++nb_octet;
    }

    for (size_t i = 0; i < (strlen(input)-start)/2; ++i) {
        char tab[3];
        strncpy(tab, (input+2*i)+start, 2);
        unsigned long new = strtoul(tab, NULL, 16);
        if(new == ULONG_MAX){
            return -1;
        }
        output[i+start] = (uint8_t)new;
        ++nb_octet;
    }

    return nb_octet;

}

int SHA256_from_string(const char *in, struct ckvs_sha *sha){
    M_REQUIRE_NON_NULL(in);
    M_REQUIRE_NON_NULL(sha);
    return hex_decode(in, sha->sha);
}

int print_json_response_stats(const char* json){
    json_object* jsonObject = json_tokener_parse(json);
    if (jsonObject == NULL){
        pps_printf("ERROR: JSON parse error, invalid format \n%s\n", json);
        return ERR_IO;
    }
    jsonKeyValue header[] = {
            {"header_string", NULL},
            {"version", NULL},
            {"table_size", NULL},
            {"threshold_entries", NULL},
            {"num_entries", NULL},
            {"keys", NULL}
    };
    for (unsigned long i= 0; i < sizeof(header)/ sizeof(jsonKeyValue); ++i) {
        int err = json_object_object_get_ex(jsonObject, header[i].key, &header[i].value);
        if (err == 0){
            pps_printf("ERROR: JSON get object error in the %s\n", header[i].key);
            json_object_put(jsonObject);
            return ERR_IO;
        }
    }

    pps_printf("%-23s: %s\n", CKVS_Header_type, json_object_get_string(header[0].value));
    pps_printf("%-23s: %u\n", CKVS_Header_version, json_object_get_int(header[1].value));
    pps_printf("%-23s: %u\n", CKVS_Header_table_size, json_object_get_int(header[2].value));
    pps_printf("%-23s: %u\n", CKVS_Header_treshold, json_object_get_int(header[3].value));
    pps_printf("%-23s: %u\n", CKVS_Header_num_entries, json_object_get_int(header[4].value));
    for (size_t i = 0; i < json_object_array_length(header[5].value); ++i) {
        pps_printf("%-10s: "STR_LENGTH_FMT(CKVS_MAXKEYLEN)"\n", CKVS_Key, json_object_get_string(json_object_array_get_idx(header[5].value, i)));
    }

    json_object_put(jsonObject);
    return ERR_NONE;
}

int check_arg_size(int optargc, int expected_size){
    if (optargc < expected_size){
        return ERR_NOT_ENOUGH_ARGUMENTS;
    }
    if (optargc > expected_size){
        return ERR_TOO_MANY_ARGUMENTS;
    }
    return ERR_NONE;
}

void freePointers(unsigned char* inBuffer, unsigned char* outBuffer){
    free(inBuffer);
    inBuffer = NULL;
    free(outBuffer);
    outBuffer = NULL;
}

