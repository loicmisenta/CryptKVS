/**
 * @file ckvs_httpd.c
 * @brief webserver
 *
 * @author Edouard Bugnion
 */

#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_utils.h"
#include "error.h"
#include "ckvs_httpd.h"
#include <assert.h>
#include "mongoose.h"
#include <json-c/json.h>
#include <string.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include "util.h"


// Handle interrupts, like Ctrl-C
static int s_signo;

#define HTTP_ERROR_CODE 500
#define HTTP_OK_CODE 200
#define HTTP_FOUND_CODE 302
#define HTTP_NOTFOUND_CODE 404

#define HM_QUERY_SIZE 1024
#define TEMP_PATH "/tmp/"

/**
 * @brief Sends an http error message
 * @param nc the http connection
 * @param err the error code corresponding the error message
*/
void mg_error_msg(struct mg_connection* nc, int err)
{
    assert(err>=0 && err < ERR_NB_ERR);
    mg_http_reply(nc, HTTP_ERROR_CODE, NULL, "Error: %s", ERR_MESSAGES[err]);
}

/**
 * @brief Handles signal sent to program, eg. Ctrl+C
 */
static void signal_handler(int signo)
{
    s_signo = signo;
}

static void handle_stats_call(struct mg_connection *nc, struct CKVS *ckvs, _unused struct mg_http_message *hm){
    if(nc == NULL || ckvs == NULL){
        debug_printf("Null pointer");
        return;
    }
    int err;
    json_object* jsonOutput = json_object_new_object();
    json_object* entries = json_object_new_array();

    char str[CKVS_MAXKEYLEN] = "";
    for (uint32_t i = 0; i < ckvs->header.table_size; ++i) {
        if (strnlen(ckvs->entries[i].key, CKVS_MAXKEYLEN) != 0 ){
            strncpy(str, ckvs->entries[i].key, CKVS_MAXKEYLEN);
            json_object_array_add(entries, json_object_new_string(str));
        }
    }

    jsonKeyValue content[] = {
            {"header_string", json_object_new_string(ckvs->header.header_string)},
            {"version", json_object_new_int((int32_t) ckvs->header.version)},
            {"table_size", json_object_new_int((int32_t) ckvs->header.table_size)},
            {"threshold_entries", json_object_new_int((int32_t) ckvs->header.threshold_entries)},
            {"num_entries", json_object_new_int((int32_t) ckvs->header.num_entries)},
            {"keys", entries}
    };

    for (unsigned long i = 0; i < sizeof(content)/ sizeof(jsonKeyValue); ++i) {
        err = json_object_object_add(jsonOutput, content[i].key, content[i].value);
        if (err < 0){
            pps_printf("ERROR: JSON build error for adding \n%s\n to json_object", content[i].key);
            json_object_put(jsonOutput);
            mg_error_msg(nc, ERR_IO);
            return;
        }
    }

    const char* json_string = json_object_to_json_string(jsonOutput);

    mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n", json_string);

    json_object_put(jsonOutput);
}

static char* get_urldecoded_argument(struct mg_http_message *hm, const char *arg){
    if(arg == NULL){
        debug_printf("Null pointer");
        return NULL;
    }
    char outBuffer[HM_QUERY_SIZE] = "";
    int err = mg_http_get_var(&hm->query, arg, outBuffer, sizeof(outBuffer));
    if(err <= 0){
        return NULL;
    }
    CURL *curl = curl_easy_init();
    if (curl){
        int decodedlen;
        char* decoded = curl_easy_unescape(curl, outBuffer, 0, &decodedlen);
        if(decoded){
            return decoded;
        }
    }
    curl_easy_cleanup(curl);
    return NULL;
}


static int get_key_authkey_entry(ckvs_entry_t** entry, struct CKVS *ckvs, struct mg_http_message *hm){

    char* key = get_urldecoded_argument(hm, "key");
    struct ckvs_sha auth_key;

    char auth_key_encoded[HM_QUERY_SIZE] = "";
    int err = mg_http_get_var(&hm->query, "auth_key", auth_key_encoded, sizeof(auth_key_encoded));
    if(err <= 0){
        free(key);
        key = NULL;
        return ERR_IO;
    }
    err = hex_decode(auth_key_encoded, auth_key.sha);
    if(err == -1){
        free(key);
        key = NULL;
        return ERR_IO;
    }


    err = ckvs_find_entry(ckvs, key, &auth_key, entry);
    if(err != ERR_NONE) {
        free(key);
        key = NULL;
        return err;
    }
    free(key);
    key = NULL;
    return ERR_NONE;

}

static void handle_get_call(struct mg_connection *nc, struct CKVS *ckvs, struct mg_http_message *hm){
    if(nc == NULL || ckvs == NULL || hm == NULL){
        debug_printf("Null pointer");
        mg_error_msg(nc, ERR_IO);
        return;
    }

    ckvs_entry_t* entry = NULL;

    int err = get_key_authkey_entry(&entry, ckvs, hm);
    if(err != ERR_NONE){
        mg_error_msg(nc, err);
        return;
    }

    //The entry has no value
    if ((entry->c2.sha[0] == '\0') && (entry->value_len == 0) && (entry->value_off == 0)){
        mg_error_msg(nc, ERR_NO_VALUE);
        return;
    }

    //create json response
    json_object* jsonOutput = json_object_new_object();

    char c2[SHA256_PRINTED_STRLEN];
    SHA256_to_string(&entry->c2, c2);

    uint8_t* data = calloc(entry->value_len, sizeof(unsigned char));
    if(data == NULL){
        json_object_put(jsonOutput);
        mg_error_msg(nc, ERR_OUT_OF_MEMORY);
        return;
    }

    err = fseek(ckvs->file, (long)entry->value_off, SEEK_SET);
    if (err != 0){
        json_object_put(jsonOutput);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    size_t read = fread(data, entry->value_len, 1, ckvs->file);
    if(read != 1){
        json_object_put(jsonOutput);
        free(data);
        data = NULL;
        mg_error_msg(nc, ERR_IO);
        return;
    }
    char* out = calloc(2 * entry->value_len + 1, sizeof(char));
    if(out == NULL){
        json_object_put(jsonOutput);
        free(data);
        data = NULL;
        free(out);
        out = NULL;
        mg_error_msg(nc, ERR_OUT_OF_MEMORY);
        return;
    }
    hex_encode(data, entry->value_len, out);

    jsonKeyValue content[] = {
            {"c2", json_object_new_string(c2)},
            {"data", json_object_new_string(out)}
    };

    for (unsigned long i = 0; i < sizeof(content)/ sizeof(jsonKeyValue); ++i) {
        err = json_object_object_add(jsonOutput, content[i].key, content[i].value);
        if (err < 0){
            pps_printf("ERROR: JSON build error for adding \n%s\n to json_object", content[i].key);
            json_object_put(jsonOutput);
            free(data);
            data = NULL;
            free(out);
            out = NULL;
            mg_error_msg(nc, ERR_IO);
            return;
        }
    }

    const char* json_string = json_object_to_json_string(jsonOutput);

    mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n", json_string);

    json_object_put(jsonOutput);
    free(data);
    data = NULL;
    free(out);
    out = NULL;
}

static void handle_set_call(struct mg_connection *nc, struct CKVS *ckvs, struct mg_http_message *hm){
    if(nc == NULL || ckvs == NULL || hm == NULL){
        debug_printf("Null pointer");
        mg_error_msg(nc, ERR_IO);
        return;
    }

    int err;
    //tant qu'il a pas finit de recevoir le fichier on upload
    if(hm->body.len != 0){
        err = mg_http_upload(nc, hm, "/tmp");
        if(err < 0){
            debug_printf("http mongoose upload error \n");
            mg_error_msg(nc, ERR_IO);
        }
    }
    else{

        //find the entry
        ckvs_entry_t entry_content;
        ckvs_entry_t* entry = &entry_content;

        err = get_key_authkey_entry(&entry, ckvs, hm);
        if(err != ERR_NONE){
            mg_error_msg(nc, err);
            return;
        }

        char name[NAME_MAX] = "";
        err = mg_http_get_var(&hm->query, "name", name, sizeof(name));
        if(err <= 0){
            debug_printf("http mongoose error \n");
            mg_error_msg(nc, ERR_IO);
            return;
        }

        size_t buffer_size;
        char *buffer_ptr = NULL;
        char temp[] = "/tmp/";
        const char* path_to_file = strncat(temp, name, strlen(name));
        err = read_value_file_content(path_to_file, &buffer_ptr, &buffer_size);
        if(err != ERR_NONE){
            free(buffer_ptr);
            buffer_ptr = NULL;
            mg_error_msg(nc, err);
            return;
        }

        json_object* jsonObject = json_tokener_parse(buffer_ptr);
        if (jsonObject == NULL){
            pps_printf("ERROR: JSON parse error, invalid format \n%s\n", buffer_ptr);
            free(buffer_ptr);
            buffer_ptr = NULL;
            mg_error_msg(nc, ERR_IO);
            return;
        }

        jsonKeyValue output[] = {
                {"c2", NULL},
                {"data", NULL}
        };
        for (unsigned long i= 0; i < sizeof(output)/ sizeof(jsonKeyValue); ++i) {
            err = json_object_object_get_ex(jsonObject, output[i].key, &output[i].value);
            if (err == 0){
                free(buffer_ptr);
                buffer_ptr = NULL;
                pps_printf("ERROR: JSON get object error in the %s\n", output[i].key);
                json_object_put(jsonObject);
                mg_error_msg(nc, ERR_IO);
                return;
            }
        }

        err = SHA256_from_string(json_object_get_string(output[0].value), &entry->c2);
        if(err == -1){
            free(buffer_ptr);
            buffer_ptr = NULL;
            json_object_put(jsonObject);
            mg_error_msg(nc, ERR_IO);
            return;
        }

        size_t size_outBufferData = ((size_t) ((json_object_get_string_len(output[1].value) / 2)));
        uint8_t * outBufferData = calloc((unsigned long)size_outBufferData, sizeof(char));

        int numOct = hex_decode(json_object_get_string((output[1].value)), outBufferData);
        if (numOct == -1){
            free(buffer_ptr);
            buffer_ptr = NULL;
            json_object_put(jsonObject);
            mg_error_msg(nc, ERR_IO);
            free(outBufferData);
            outBufferData = NULL;
            return;
        }
        err = ckvs_write_encrypted_value(ckvs, entry, outBufferData, (uint64_t)numOct);
        if(err != ERR_NONE){
            free(buffer_ptr);
            buffer_ptr = NULL;
            free(outBufferData);
            outBufferData = NULL;
            mg_error_msg(nc, err);
            return;
        }

        free(buffer_ptr);
        buffer_ptr = NULL;
        free(outBufferData);
        outBufferData = NULL;
        mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n", "");
    }
}

// ======================================================================
/**
 * @brief Handles server events (eg HTTP requests).
 * For more check https://cesanta.com/docs/#event-handler-function
 */
static void ckvs_event_handler(struct mg_connection *nc, int ev, void *ev_data, void *fn_data){
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    struct CKVS *ckvs = (struct CKVS*) fn_data;

    if (ev != MG_EV_POLL)
        debug_printf("Event received %d", ev);

    switch (ev) {
    case MG_EV_POLL:
    case MG_EV_CLOSE:
    case MG_EV_READ:
    case MG_EV_WRITE:
    case MG_EV_HTTP_CHUNK:
        break;

    case MG_EV_ERROR:
        debug_printf("httpd mongoose error \n");
        break;
    case MG_EV_ACCEPT:
        // students: no need to implement SSL
        assert(ckvs->listening_addr);
        debug_printf("accepting connection at %s\n", ckvs->listening_addr);
        assert (mg_url_is_ssl(ckvs->listening_addr) == 0);
        break;

    case MG_EV_HTTP_MSG:
        if(mg_http_match_uri(hm, "/stats")){
            handle_stats_call(nc, ckvs, hm);
        }
        else if(mg_http_match_uri(hm, "/get")){
            handle_get_call(nc, ckvs, hm);
        }
        else if(mg_http_match_uri(hm, "/set")){
            handle_set_call(nc, ckvs, hm);
        }
        else{
            mg_error_msg(nc, NOT_IMPLEMENTED);
        }
        break;

    default:
        fprintf(stderr, "ckvs_event_handler %u\n", ev);
        assert(0);
    }
}

// ======================================================================
int ckvs_httpd_mainloop(const char *filename, int optargc, char **optargv)
{
    if (optargc < 1)
        return ERR_NOT_ENOUGH_ARGUMENTS;
    else if (optargc > 1)
        return ERR_TOO_MANY_ARGUMENTS;

    /* Create server */

    signal(SIGINT, signal_handler); //adds interruption signals to the signal handler
    signal(SIGTERM, signal_handler);

    struct CKVS ckvs;
    int err = ckvs_open(filename, &ckvs);

    if (err != ERR_NONE) {
        return err;
    }

    ckvs.listening_addr = optargv[0];

    struct mg_mgr mgr;
    struct mg_connection *c;

    mg_mgr_init(&mgr);

    c = mg_http_listen(&mgr, ckvs.listening_addr, ckvs_event_handler, &ckvs);
    if (c==NULL) {
        debug_printf("Error starting server on address %s\n", ckvs.listening_addr);
        ckvs_close(&ckvs);
        return ERR_IO;
    }

    debug_printf("Starting CKVS server on %s for database %s\n", ckvs.listening_addr, filename);

    while (s_signo == 0) {
        mg_mgr_poll(&mgr, 1000); //infinite loop as long as no termination signal occurs
    }
    mg_mgr_free(&mgr);
    ckvs_close(&ckvs);
    debug_printf("Exiting HTTPD server\n");
    return ERR_NONE;
}

