#include <malloc.h>
#include "ckvs_client.h"
#include "error.h"
#include "util.h"
#include "ckvs_utils.h"
#include "ckvs_rpc.h"
#include "ckvs_crypto.h"
#include <json-c/json.h>
#include "ckvs_io.h"
#include "openssl/rand.h"
#include "openssl/evp.h"

#define GET_URL_STATS "/stats"
#define MAX_FORMAT_URL_SIZE 43
int ckvs_client_get_set(const char *url, const char *key, const char *pwd, const char* set_value);
int ckvs_client_do_get(ckvs_connection_t* ckvsConnection, ckvs_memrecord_t* ckvs_memrecord);
int ckvs_client_do_set(ckvs_connection_t* ckvsConnection, ckvs_memrecord_t* ckvs_memrecord, char* str, const char* set_value);

int ckvs_client_stats(const char *url, int optargc, _unused char **optargv){
    M_REQUIRE_NON_NULL(url);

    int err = check_arg_size(optargc, ARG_SIZE_STATS);
    if(err != ERR_NONE){
        return err;
    }
    ckvs_connection_t ckvsConnection;
    err = ckvs_rpc_init(&ckvsConnection, url);
    if(err != ERR_NONE){
        return err;
    }
    err = ckvs_rpc(&ckvsConnection, GET_URL_STATS);
    if(err != ERR_NONE){
        ckvs_rpc_close(&ckvsConnection);
        return err;
    }
    err = print_json_response_stats(ckvsConnection.resp_buf);
    if (err != ERR_NONE){
        ckvs_rpc_close(&ckvsConnection);
        return err;
    }

    ckvs_rpc_close(&ckvsConnection);
    return ERR_NONE;
}

int ckvs_client_get(const char *url, int optargc, char **optargv) {
    M_REQUIRE_NON_NULL(url);
    M_REQUIRE_NON_NULL(optargv);

    int err = check_arg_size(optargc, ARG_SIZE_GET);
    if (err != ERR_NONE) {
        return err;
    }
    const char *key = optargv[0];
    const char *pwd = optargv[1];

    return ckvs_client_get_set(url, key, pwd, NULL);
}

int ckvs_client_set(const char *url, int optargc, char **optargv){
    M_REQUIRE_NON_NULL(url);
    M_REQUIRE_NON_NULL(optargv);

    const char* key = optargv[0];
    const char* pwd = optargv[1];
    const char* valuefilename = optargv[2];
    int err = check_arg_size(optargc, ARG_SIZE_SET);
    if(err != ERR_NONE){
        return err;
    }

    //read the content from the given file
    size_t buffer_size;
    char *buffer_ptr = NULL;
    err = read_value_file_content(valuefilename, &buffer_ptr, &buffer_size);
    if (err != ERR_NONE){
        return err;
    }

    return ckvs_client_get_set(url, key, pwd, buffer_ptr);
}

int ckvs_client_get_set(const char *url, const char *key, const char *pwd, const char* set_value){
    M_REQUIRE_NON_NULL(url);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);

    int err;
    ckvs_connection_t ckvsConnection;
    ckvs_memrecord_t ckvs_memrecord;

    //create a new connection
    err =  ckvs_rpc_init(&ckvsConnection, url);
    if (err != ERR_NONE){
        return err;
    }

    //encrypt the password
    err = ckvs_client_encrypt_pwd(&ckvs_memrecord, key, pwd);
    if (err != ERR_NONE){
        ckvs_rpc_close(&ckvsConnection);
        return err;
    }

    //remove the spaces from the key
    key = curl_easy_escape(ckvsConnection.curl, key, 0);
    if(key == NULL){
        ckvs_rpc_close(&ckvsConnection);
        return ERR_OUT_OF_MEMORY;
    }

    //transform the authkey into a string that can be used in the url request
    char auth_key[SHA256_PRINTED_STRLEN] = "";
    SHA256_to_string(&ckvs_memrecord.auth_key, auth_key);
    char* str = calloc(MAX_FORMAT_URL_SIZE + strlen(key) + strlen(auth_key), sizeof(char));

    //make the request with the corresponding url (get)
    if (set_value == NULL){
        sprintf(str, "/get?key=%s&auth_key=%s", key, auth_key);
        //make the web request and give it to do get, so it can print the message
        err = ckvs_rpc(&ckvsConnection, str);
        if(err != ERR_NONE){
            ckvs_rpc_close(&ckvsConnection);
            free(str);
            str = NULL;
            return err;
        }

        //from the returned message get C2 and data
        err = ckvs_client_do_get(&ckvsConnection, &ckvs_memrecord);
        if(err != ERR_NONE){
            ckvs_rpc_close(&ckvsConnection);
            free(str);
            str = NULL;
            return err;
        }
    }

    //make the post with the corresponding url (set)
    if (set_value != NULL){
        sprintf(str, "/set?name=data.json&offset=0&key=%s&auth_key=%s", key, auth_key);
        err = ckvs_client_do_set(&ckvsConnection, &ckvs_memrecord, str, set_value);
        if(err != ERR_NONE){
            ckvs_rpc_close(&ckvsConnection);
            free(str);
            str = NULL;
            return err;
        }
    }

    ckvs_rpc_close(&ckvsConnection);
    free(str);
    str = NULL;
    return ERR_NONE;
}

int ckvs_client_do_get(ckvs_connection_t* ckvsConnection, ckvs_memrecord_t* ckvs_memrecord){
    json_object* jsonObject = json_tokener_parse(ckvsConnection->resp_buf);
    int err;
    if (jsonObject == NULL){
        pps_printf("ERROR: JSON parse error, invalid format \n%s\n", ckvsConnection->resp_buf);
        return ERR_IO;
    }

    jsonKeyValue output[] = {
            {"c2", NULL},
            {"data", NULL}
    };
    for (unsigned long i= 0; i < sizeof(output)/ sizeof(jsonKeyValue); ++i) {
        err = json_object_object_get_ex(jsonObject, output[i].key, &output[i].value);
        if (err == 0){
            pps_printf("ERROR: JSON get object error in the %s\n", output[i].key);
            json_object_put(jsonObject);
            return ERR_IO;
        }
    }
    ckvs_sha_t C2;
    err = SHA256_from_string(json_object_get_string(output[0].value), &C2);
    if(err == -1){
        json_object_put(jsonObject);
        return ERR_IO;
    }

    size_t size_outBufferData = ((size_t) ((json_object_get_string_len(output[1].value) / 2)));
    uint8_t * outBufferData = calloc((unsigned long)size_outBufferData, sizeof(char));

    int numOct = hex_decode(json_object_get_string((output[1].value)), outBufferData);
    if (numOct == -1){
        json_object_put(jsonObject);
        return ERR_IO;
    }
    uint8_t * outBufferDecrypt = calloc((unsigned long) numOct + EVP_MAX_BLOCK_LENGTH, sizeof(char));

    err = ckvs_client_compute_masterkey(ckvs_memrecord, &C2);
    if(err != ERR_NONE){
        json_object_put(jsonObject);
        freePointers(outBufferData, outBufferDecrypt);
        return err;
    }
        size_t outSize = 0;
    err = ckvs_client_crypt_value(ckvs_memrecord, 0, outBufferData, size_outBufferData, outBufferDecrypt, &outSize);
    if(err != ERR_NONE){
        json_object_put(jsonObject);
        freePointers(outBufferData, outBufferDecrypt);
        return err;
    }
    pps_printf("%s", outBufferDecrypt);
    freePointers(outBufferData, outBufferDecrypt);
    return ERR_NONE;
}

int ckvs_client_do_set(ckvs_connection_t* ckvsConnection, ckvs_memrecord_t* ckvs_memrecord, char* str, const char* set_value){
    ckvs_sha_t C2;
    int err = RAND_bytes(C2.sha, SHA256_DIGEST_LENGTH);
    if(err != 1){
        return ERR_IO;
    }
    char c2[SHA256_PRINTED_STRLEN];
    SHA256_to_string(&C2, c2);

    err = ckvs_client_compute_masterkey(ckvs_memrecord, &C2);
    if(err != ERR_NONE){
        return err;
    }

    size_t max_inBufferLen = strlen(set_value) + EVP_MAX_BLOCK_LENGTH;
    unsigned char* outBuffer = calloc(max_inBufferLen, 1);
    if(outBuffer == NULL){
        return ERR_OUT_OF_MEMORY;
    }

    err = ckvs_client_crypt_value(ckvs_memrecord, 1, (const unsigned char*)set_value, strlen(set_value) + 1, outBuffer, &max_inBufferLen);
    if(err != ERR_NONE){
        free(outBuffer);
        outBuffer = NULL;
        return err;
    }

    char* buffer = calloc(max_inBufferLen * 2 + 1, 1);
    if (buffer == NULL){
        free(outBuffer);
        outBuffer = NULL;
        return ERR_IO;
    }
    hex_encode(outBuffer, max_inBufferLen, buffer);


    //Creates the json struct containing c2 and the data
    json_object* jsonOutput = json_object_new_object();
    jsonKeyValue content[] = {
            {"c2", json_object_new_string(c2)},
            {"data", json_object_new_string((const char*) buffer)}
    };
    for (unsigned long i = 0; i < sizeof(content)/ sizeof(jsonKeyValue); ++i) {
        err = json_object_object_add(jsonOutput, content[i].key, content[i].value);
        if (err < 0){
            pps_printf("ERROR: JSON build error for adding \n%s\n to json_object", content[i].key);
            json_object_put(jsonOutput);
            free(outBuffer);
            outBuffer = NULL;
            free(buffer);
            buffer = NULL;
            return ERR_IO;
        }
    }
    const char* json_string = json_object_to_json_string(jsonOutput);

    err = ckvs_post(ckvsConnection, str, json_string);
    if (err != ERR_NONE){
        json_object_put(jsonOutput);
        free(outBuffer);
        outBuffer = NULL;
        free(buffer);
        buffer = NULL;
        return err;
    }

    json_object_put(jsonOutput);
    free(outBuffer);
    outBuffer = NULL;
    free(buffer);
    buffer = NULL;
    return ERR_NONE;
}

int ckvs_client_new(_unused const char *url, _unused int optargc, _unused char **optargv){
    return NOT_IMPLEMENTED;
}

