/*
 * cryptkvs -- main ; argument parsing and dispatch ; etc.
 */

#include <stdio.h>
#include "error.h"
#include "ckvs_local.h"
#include "ckvs_utils.h"
#include "ckvs_client.h"
#include "ckvs_httpd.h"

/* *************************************************** *
 * TODO WEEK 09-11: Add then augment usage messages    *
 * *************************************************** */

/* *************************************************** *
 * TODO WEEK 04-07: add message                        *
 * TODO WEEK 09: Refactor usage()                      *
 * *************************************************** */
#define HTTP "http://"
#define HTTP_SIZE 7
#define HTTPS "https://"
#define HTTPS_SIZE 8


typedef int (*ckvs_command)(const char* filename, int optargc, char* optargv[]);

typedef struct{
    const char* str_command;
    const char* description;
    const ckvs_command command_local;
    const ckvs_command command_client;
}ckvs_command_mapping;

const ckvs_command_mapping commands[] = {
        {"stats", "\t -cryptkvs [<database>|<url>] stats\n", ckvs_local_stats, ckvs_client_stats},
        {"get", "\t -cryptkvs [<database>|<url>] get <key> <password>\n", ckvs_local_get, ckvs_client_get},
        {"set", "\t -cryptkvs [<database>|<url>] set <key> <password> <filename>\n", ckvs_local_set, ckvs_client_set},
        {"new", "\t -cryptkvs [<database>|<url>] new <key> <password>\n", ckvs_local_new, ckvs_client_new},
        {"httpd", "\t -cryptkvs <database> httpd <server port>\n", ckvs_httpd_mainloop, NULL}
};

//function that returns the correct function given a keyword (get, set, stats, new) or NULL if not found
ckvs_command get_function(const char* cmd, const char* db_filename){
    for (unsigned int i = 0; i < sizeof(commands)/sizeof(ckvs_command_mapping); ++i) {
        if (strcmp(cmd, commands[i].str_command) == 0){
            if (strncmp(db_filename, HTTP, HTTP_SIZE) == 0 || strncmp(db_filename, HTTPS, HTTPS_SIZE) == 0){
                return commands[i].command_client;
            }
            return commands[i].command_local;
        }
    }
    return NULL;
}

static void usage(const char *execname, int err)
{
    if (err == ERR_INVALID_COMMAND) {
        pps_printf("Available commands:\n");
        for (unsigned int i = 0; i < sizeof(commands)/sizeof(ckvs_command_mapping); ++i) {
            pps_printf("%s", commands[i].description);
        }
        pps_printf("\n");
    } else if (err >= 0 && err < ERR_NB_ERR) {
        pps_printf("%s exited with error: %s\n\n\n", execname, ERR_MESSAGES[err]);
    } else {
        pps_printf("%s exited with error: %d (out of range)\n\n\n", execname, err);
    }
}

/* *************************************************** *
 * TODO WEEK 04-11: Add more commands                  *
 * TODO WEEK 09: Refactor ckvs_local_*** commands      *
 * *************************************************** */
/**
 * @brief Runs the command requested by the user in the command line, or returns ERR_INVALID_COMMAND if the command is not found.
 *
 * @param argc (int) the number of arguments in the command line
 * @param argv (char*[]) the arguments of the command line, as passed to main()
 */
int ckvs_do_one_cmd(int argc, char *argv[]){
    if (argc < 3) return ERR_INVALID_COMMAND;

    const char* db_filename = argv[1];
    const char* cmd = argv[2];
    int optargc = argc - 3;
    char** optargv = argv + 3;

    int (*local_function)(const char* filename, int optargc, char* optargv[]);

    local_function = get_function(cmd, db_filename);
    if (local_function == NULL){
        return ERR_INVALID_COMMAND;
    }

    return ((*local_function)(db_filename, optargc, optargv));
}

#ifndef FUZZ
/**
 * @brief main function, runs the requested command and prints the resulting error if any.
 */
int main(int argc, char *argv[]){
    int ret = ckvs_do_one_cmd(argc, argv);
    if (ret != ERR_NONE) {
        usage(argv[0], ret);
    }
    return ret;
}
#endif
