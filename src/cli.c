#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include "storj.h"

#define STORJ_THREADPOOL_SIZE "64"

typedef struct {
    char *user;
    char *pass;
    char *host;
    char *mnemonic;
    char *key;
} user_options_t;

#ifndef errno
extern int errno;
#endif

static inline void noop() {};

#define HELP_TEXT "usage: storj [<options>] <command> [<args>]\n\n"     \
    "These are common Storj commands for various situations:\n\n"       \
    "setting up users profiles\n"                                       \
    "  register                  setup a new storj bridge user\n"       \
    "  import-keys               import existing user\n"                \
    "  export-keys               export bridge user, password and "     \
    "encryption keys\n\n"                                               \
    "working with buckets and files\n"                                  \
    "  list-buckets\n"                                                  \
    "  list-files <bucket-id>\n"                                        \
    "  remove-file <bucket-id> <file-id>\n"                             \
    "  add-bucket <name> \n"                                            \
    "  remove-bucket <bucket-id>\n"                                     \
    "  list-mirrors <bucket-id> <file-id>\n\n"                          \
    "downloading and uploading files\n"                                 \
    "  upload-file <bucket-id> <path>\n"                                \
    "  download-file <bucket-id> <file-id> <path>\n"                    \
    "bridge api information\n"                                          \
    "  get-info\n\n"                                                    \
    "options:\n"                                                        \
    "  -h, --help                output usage information\n"            \
    "  -v, --version             output the version number\n"           \
    "  -u, --url <url>           set the base url for the api\n"        \
    "  -p, --proxy <url>         set the socks proxy "                  \
    "(e.g. <[protocol://][user:password@]proxyhost[:port]>)\n"          \
    "  -l, --log <level>         set the log level (default 0)\n"       \
    "  -d, --debug               set the debug log level\n\n"           \
    "environment variables:\n"                                          \
    "  STORJ_KEYPASS             imported user settings passphrase\n"   \
    "  STORJ_BRIDGE              the bridge host "                      \
    "(e.g. https://api.storj.io)\n"                                     \
    "  STORJ_BRIDGE_USER         bridge username\n"                     \
    "  GENARO_APIKEY                 bridge api key\n"                  \
    "  GENARO_SECRETKEY              bridge secret key\n"               \
    "  STORJ_BRIDGE_PASS         bridge password\n"                     \
    "  STORJ_ENCRYPTION_KEY      file encryption key\n\n"


#define CLI_VERSION "libstorj-2.0.0-beta"

static void json_logger(const char *message, int level, void *handle)
{
    printf("{\"message\": \"%s\", \"level\": %i, \"timestamp\": %" PRIu64 "}\n",
           message, level, storj_util_timestamp());
}

static char *get_home_dir()
{
#ifdef _WIN32
    return getenv("USERPROFILE");
#else
    return getenv("HOME");
#endif
}

static int make_user_directory(char *path)
{
    struct stat st = {0};
    if (stat(path, &st) == -1) {
#if _WIN32
        int mkdir_status = _mkdir(path);
        if (mkdir_status) {
            printf("Unable to create directory %s: code: %i.\n",
                   path,
                   mkdir_status);
            return 1;
        }
#else
        if (mkdir(path, 0700)) {
            printf("Unable to create directory %s: reason: %s\n",
                   path,
                   strerror(errno));
            return 1;
        }
#endif
    }
    return 0;
}

static const char *get_filename_separator(const char *file_path)
{
    const char *file_name = NULL;
#ifdef _WIN32
    file_name = strrchr(file_path, '\\');
    if (!file_name) {
        file_name = strrchr(file_path, '/');
    }
    if (!file_name && file_path) {
        file_name = file_path;
    }
    if (!file_name) {
        return NULL;
    }
    if (file_name[0] == '\\' || file_name[0] == '/') {
        file_name++;
    }
#else
    file_name = strrchr(file_path, '/');
    if (!file_name && file_path) {
        file_name = file_path;
    }
    if (!file_name) {
        return NULL;
    }
    if (file_name[0] == '/') {
        file_name++;
    }
#endif
    return file_name;
}

static int get_user_auth_location(char *host, char **root_dir, char **user_file)
{
    char *home_dir = get_home_dir();
    if (home_dir == NULL) {
        return 1;
    }

    int len = strlen(home_dir) + strlen("/.storj/");
    *root_dir = calloc(len + 1, sizeof(char));
    if (!*root_dir) {
        return 1;
    }

    strcpy(*root_dir, home_dir);
    strcat(*root_dir, "/.storj/");

    len = strlen(*root_dir) + strlen(host) + strlen(".json");
    *user_file = calloc(len + 1, sizeof(char));
    if (!*user_file) {
        return 1;
    }

    strcpy(*user_file, *root_dir);
    strcat(*user_file, host);
    strcat(*user_file, ".json");

    return 0;
}

static void get_input(char *line)
{
    if (fgets(line, BUFSIZ, stdin) == NULL) {
        line[0] = '\0';
    } else {
        int len = strlen(line);
        if (len > 0) {
            char *last = strrchr(line, '\n');
            if (last) {
                last[0] = '\0';
            }
            last = strrchr(line, '\r');
            if (last) {
                last[0] = '\0';
            }
        }
    }
}

static int generate_mnemonic(char **mnemonic)
{
    char *strength_str = NULL;
    int strength = 0;
    int status = 0;

    printf("We now need to create an secret key used for encrypting " \
           "files.\nPlease choose strength from: 128, 160, 192, 224, 256\n\n");

    while (strength % 32 || strength < 128 || strength > 256) {
        strength_str = calloc(BUFSIZ, sizeof(char));
        printf("Strength: ");
        get_input(strength_str);

        if (strength_str != NULL) {
            strength = atoi(strength_str);
        }

        free(strength_str);
    }

    if (*mnemonic) {
        free(*mnemonic);
    }

    *mnemonic = NULL;

    int generate_code = storj_mnemonic_generate(strength, mnemonic);
    if (*mnemonic == NULL || generate_code == 0) {
        printf("Failed to generate encryption key.\n");
        status = 1;
        status = generate_mnemonic(mnemonic);
    }

    return status;
}

static int get_password(char *password, int mask)
{
    int max_pass_len = 512;

#ifdef _WIN32
    HANDLE hstdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    DWORD prev_mode = 0;
    GetConsoleMode(hstdin, &mode);
    GetConsoleMode(hstdin, &prev_mode);
    SetConsoleMode(hstdin, mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT));
#else
    static struct termios prev_terminal;
    static struct termios terminal;

    tcgetattr(STDIN_FILENO, &prev_terminal);

    memcpy (&terminal, &prev_terminal, sizeof(struct termios));
    terminal.c_lflag &= ~(ICANON | ECHO);
    terminal.c_cc[VTIME] = 0;
    terminal.c_cc[VMIN] = 1;
    tcsetattr(STDIN_FILENO, TCSANOW, &terminal);
#endif

    size_t idx = 0;         /* index, number of chars in read   */
    int c = 0;

    const char BACKSPACE = 8;
    const char RETURN = 13;

    /* read chars from fp, mask if valid char specified */
#ifdef _WIN32
    long unsigned int char_read = 0;
    while ((ReadConsole(hstdin, &c, 1, &char_read, NULL) && c != '\n' && c != RETURN && c != EOF && idx < max_pass_len - 1) ||
            (idx == max_pass_len - 1 && c == BACKSPACE))
#else
    while (((c = fgetc(stdin)) != '\n' && c != EOF && idx < max_pass_len - 1) ||
            (idx == max_pass_len - 1 && c == 127))
#endif
    {
        if (c != 127 && c != BACKSPACE) {
            if (31 < mask && mask < 127)    /* valid ascii char */
                fputc(mask, stdout);
            password[idx++] = c;
        } else if (idx > 0) {         /* handle backspace (del)   */
            if (31 < mask && mask < 127) {
                fputc(0x8, stdout);
                fputc(' ', stdout);
                fputc(0x8, stdout);
            }
            password[--idx] = 0;
        }
    }
    password[idx] = 0; /* null-terminate   */

    // go back to the previous settings
#ifdef _WIN32
    SetConsoleMode(hstdin, prev_mode);
#else
    tcsetattr(STDIN_FILENO, TCSANOW, &prev_terminal);
#endif

    return idx; /* number of chars in passwd    */
}

static int get_password_verify(char *prompt, char *password, int count)
{
    printf("%s", prompt);
    char first_password[BUFSIZ];
    get_password(first_password, '*');

    printf("\nAgain to verify: ");
    char second_password[BUFSIZ];
    get_password(second_password, '*');

    int match = strcmp(first_password, second_password);
    strncpy(password, first_password, BUFSIZ);

    if (match == 0) {
        return 0;
    } else {
        printf("\nPassphrases did not match. ");
        count++;
        if (count > 3) {
            printf("\n");
            return 1;
        }
        printf("Try again...\n");
        return get_password_verify(prompt, password, count);
    }
}

void close_signal(uv_handle_t *handle)
{
    ((void)0);
}

static void file_progress(double progress,
                          uint64_t downloaded_bytes,
                          uint64_t total_bytes,
                          void *handle)
{
    int bar_width = 70;

    if (progress == 0 && downloaded_bytes == 0) {
        printf("Preparing File...");
        fflush(stdout);
        return;
    }

    printf("\r[");
    int pos = bar_width * progress;
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) {
            printf("=");
        } else if (i == pos) {
            printf(">");
        } else {
            printf(" ");
        }
    }
    printf("] %.*f%%", 2, progress * 100);

    fflush(stdout);
}

static void upload_file_complete(int status, char *file_id, void *handle)
{
    printf("\n");
    if (status != 0) {
        printf("Upload failure: %s\n", storj_strerror(status));
        exit(status);
    }

    printf("Upload Success! File ID: %s\n", file_id);

    free(file_id);

    exit(0);
}

void upload_signal_handler(uv_signal_t *req, int signum)
{
    storj_upload_state_t *state = req->data;
    storj_bridge_store_file_cancel(state);
    if (uv_signal_stop(req)) {
        printf("Unable to stop signal\n");
    }
    uv_close((uv_handle_t *)req, close_signal);
}

static int upload_file(storj_env_t *env, char *bucket_id, const char *file_path)
{
    FILE *fd = fopen(file_path, "r");

    if (!fd) {
        printf("Invalid file path: %s\n", file_path);
    }

    const char *file_name = get_filename_separator(file_path);

    if (!file_name) {
        file_name = file_path;
    }

    // Upload opts env variables:
    char *prepare_frame_limit = getenv("STORJ_PREPARE_FRAME_LIMIT");
    char *push_frame_limit = getenv("STORJ_PUSH_FRAME_LIMIT");
    char *push_shard_limit = getenv("STORJ_PUSH_SHARD_LIMIT");
    char *rs = getenv("STORJ_REED_SOLOMON");

    storj_upload_opts_t upload_opts = {
        .prepare_frame_limit = (prepare_frame_limit) ? atoi(prepare_frame_limit) : 1,
        .push_frame_limit = (push_frame_limit) ? atoi(push_frame_limit) : 64,
        .push_shard_limit = (push_shard_limit) ? atoi(push_shard_limit) : 64,
        .rs = (!rs) ? true : (strcmp(rs, "false") == 0) ? false : true,
        .bucket_id = bucket_id,
        .file_name = file_name,
        .fd = fd
    };

    uv_signal_t *sig = malloc(sizeof(uv_signal_t));
    if (!sig) {
        return 1;
    }
    uv_signal_init(env->loop, sig);
    uv_signal_start(sig, upload_signal_handler, SIGINT);



    storj_progress_cb progress_cb = (storj_progress_cb)noop;
    if (env->log_options->level == 0) {
        progress_cb = file_progress;
    }

    storj_upload_state_t *state = storj_bridge_store_file(env,
                                                          &upload_opts,
                                                          NULL,
                                                          progress_cb,
                                                          upload_file_complete);

    if (!state) {
        return 1;
    }

    sig->data = state;

    return state->error_status;
}

static void download_file_complete(int status, FILE *fd, void *handle)
{
    printf("\n");
    fclose(fd);
    if (status) {
        // TODO send to stderr
        switch(status) {
            case STORJ_FILE_DECRYPTION_ERROR:
                printf("Unable to properly decrypt file, please check " \
                       "that the correct encryption key was " \
                       "imported correctly.\n\n");
                break;
            default:
                printf("Download failure: %s\n", storj_strerror(status));
        }

        exit(status);
    }
    printf("Download Success!\n");
    exit(0);
}

void download_signal_handler(uv_signal_t *req, int signum)
{
    storj_download_state_t *state = req->data;
    storj_bridge_resolve_file_cancel(state);
    if (uv_signal_stop(req)) {
        printf("Unable to stop signal\n");
    }
    uv_close((uv_handle_t *)req, close_signal);
}

static int download_file(storj_env_t *env, char *bucket_id,
                         char *file_id, char *path)
{
    FILE *fd = NULL;

    if (path) {
        char user_input[BUFSIZ];
        memset(user_input, '\0', BUFSIZ);

        if(access(path, F_OK) != -1 ) {
            printf("Warning: File already exists at path [%s].\n", path);
            while (strcmp(user_input, "y") != 0 && strcmp(user_input, "n") != 0)
            {
                memset(user_input, '\0', BUFSIZ);
                printf("Would you like to overwrite [%s]: [y/n] ", path);
                get_input(user_input);
            }

            if (strcmp(user_input, "n") == 0) {
                printf("\nCanceled overwriting of [%s].\n", path);
                return 1;
            }

            unlink(path);
        }

        fd = fopen(path, "w+");
    } else {
        fd = stdout;
    }

    if (fd == NULL) {
        // TODO send to stderr
        printf("Unable to open %s: %s\n", path, strerror(errno));
        return 1;
    }

    uv_signal_t *sig = malloc(sizeof(uv_signal_t));
    uv_signal_init(env->loop, sig);
    uv_signal_start(sig, download_signal_handler, SIGINT);

    storj_progress_cb progress_cb = (storj_progress_cb)noop;
    if (path && env->log_options->level == 0) {
        progress_cb = file_progress;
    }

    storj_download_state_t *state = storj_bridge_resolve_file(env, bucket_id,
                                                              file_id, fd, NULL,
                                                              progress_cb,
                                                              download_file_complete);
    if (!state) {
        return 1;
    }
    sig->data = state;

    return state->error_status;
}

static void list_mirrors_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    if (req->status_code != 200) {
        printf("Request failed with status code: %i\n",
               req->status_code);
    }

    if (req->response == NULL) {
        free(req);
        free(work_req);
        printf("Failed to list mirrors.\n");
        exit(1);
    }

    int num_mirrors = json_object_array_length(req->response);

    struct json_object *shard;
    struct json_object *established;
    struct json_object *available;
    struct json_object *item;
    struct json_object *hash;
    struct json_object *contract;
    struct json_object *address;
    struct json_object *port;
    struct json_object *node_id;

    for (int i = 0; i < num_mirrors; i++) {
        shard = json_object_array_get_idx(req->response, i);
        json_object_object_get_ex(shard, "established",
                                 &established);
        int num_established =
            json_object_array_length(established);
        for (int j = 0; j < num_established; j++) {
            item = json_object_array_get_idx(established, j);
            if (j == 0) {
                json_object_object_get_ex(item, "shardHash",
                                          &hash);
                printf("Shard %i: %s\n", i, json_object_get_string(hash));
            }
            json_object_object_get_ex(item, "contract", &contract);
            json_object_object_get_ex(contract, "farmer_id", &node_id);

            const char *node_id_str = json_object_get_string(node_id);
            printf("\tnodeID: %s\n", node_id_str);
        }
        printf("\n\n");
    }

    json_object_put(req->response);
    free(req->path);
    free(req);
    free(work_req);
}

static int import_keys(user_options_t *options)
{
    int status = 0;
    char *host = options->host ? strdup(options->host) : NULL;
    char *user = options->user ? strdup(options->user) : NULL;
    char *pass = options->pass ? strdup(options->pass) : NULL;
    char *key = options->key ? strdup(options->key) : NULL;
    char *mnemonic = options->mnemonic ? strdup(options->mnemonic): NULL;
    char *mnemonic_input = NULL;
    char *user_file = NULL;
    char *root_dir = NULL;
    int num_chars;

    char *user_input = calloc(BUFSIZ, sizeof(char));
    if (user_input == NULL) {
        printf("Unable to allocate buffer\n");
        status = 1;
        goto clear_variables;
    }

    if (get_user_auth_location(host, &root_dir, &user_file)) {
        printf("Unable to determine user auth filepath.\n");
        status = 1;
        goto clear_variables;
    }

    struct stat st;
    if (stat(user_file, &st) == 0) {
        printf("Would you like to overwrite the current settings?: [y/n] ");
        get_input(user_input);
        while (strcmp(user_input, "y") != 0 && strcmp(user_input, "n") != 0)
        {
            printf("Would you like to overwrite the current settings?: [y/n] ");
            get_input(user_input);
        }

        if (strcmp(user_input, "n") == 0) {
            printf("\nCanceled overwriting of stored credentials.\n");
            status = 1;
            goto clear_variables;
        }
    }

    if (!user) {
        printf("Bridge username (email): ");
        get_input(user_input);
        num_chars = strlen(user_input);
        user = calloc(num_chars + 1, sizeof(char));
        if (!user) {
            status = 1;
            goto clear_variables;
        }
        memcpy(user, user_input, num_chars * sizeof(char));
    }

    if (!pass) {
        printf("Bridge password: ");
        pass = calloc(BUFSIZ, sizeof(char));
        if (!pass) {
            status = 1;
            goto clear_variables;
        }
        get_password(pass, '*');
        printf("\n");
    }

    if (!mnemonic) {
        mnemonic_input = calloc(BUFSIZ, sizeof(char));
        if (!mnemonic_input) {
            status = 1;
            goto clear_variables;
        }

        printf("\nIf you've previously uploaded files, please enter your" \
               " existing encryption key (12 to 24 words). \nOtherwise leave" \
               " the field blank to generate a new key.\n\n");

        printf("Encryption key: ");
        get_input(mnemonic_input);
        num_chars = strlen(mnemonic_input);

        if (num_chars == 0) {
            printf("\n");
            generate_mnemonic(&mnemonic);
            printf("\n");

            printf("Encryption key: %s\n", mnemonic);
            printf("\n");
            printf("Please make sure to backup this key in a safe location. " \
                   "If the key is lost, the data uploaded will also be lost.\n\n");
        } else {
            mnemonic = calloc(num_chars + 1, sizeof(char));
            if (!mnemonic) {
                status = 1;
                goto clear_variables;
            }
            memcpy(mnemonic, mnemonic_input, num_chars * sizeof(char));
        }

        if (!storj_mnemonic_check(mnemonic)) {
            printf("Encryption key integrity check failed.\n");
            status = 1;
            goto clear_variables;
        }
    }

    if (!key) {
        key = calloc(BUFSIZ, sizeof(char));
        printf("We now need to save these settings. Please enter a passphrase" \
               " to lock your settings.\n\n");
        if (get_password_verify("Unlock passphrase: ", key, 0)) {
            printf("Unable to store encrypted authentication.\n");
            status = 1;
            goto clear_variables;
        }
        printf("\n");
    }

    if (make_user_directory(root_dir)) {
        status = 1;
        goto clear_variables;
    }

    if (storj_encrypt_write_auth(user_file, key, user, pass, mnemonic)) {
        status = 1;
        printf("Failed to write to disk\n");
        goto clear_variables;
    }

    printf("Successfully stored bridge username, password, and encryption "\
           "key to %s\n\n",
           user_file);

clear_variables:
    if (user) {
        free(user);
    }
    if (user_input) {
        free(user_input);
    }
    if (pass) {
        free(pass);
    }
    if (mnemonic) {
        free(mnemonic);
    }
    if (mnemonic_input) {
        free(mnemonic_input);
    }
    if (key) {
        free(key);
    }
    if (root_dir) {
        free(root_dir);
    }
    if (user_file) {
        free(user_file);
    }
    if (host) {
        free(host);
    }

    return status;
}

static void register_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    if (req->status_code != 201) {
        printf("Request failed with status code: %i\n",
               req->status_code);
        struct json_object *error;
        json_object_object_get_ex(req->response, "error", &error);
        printf("Error: %s\n", json_object_get_string(error));

        user_options_t *handle = (user_options_t *) req->handle;
        free(handle->user);
        free(handle->host);
        free(handle->pass);
    } else {
        struct json_object *email;
        json_object_object_get_ex(req->response, "email", &email);
        printf("\n");
        printf("Successfully registered %s, please check your email "\
               "to confirm.\n", json_object_get_string(email));

        // save credentials
        char *mnemonic = NULL;
        printf("\n");
        generate_mnemonic(&mnemonic);
        printf("\n");

        printf("Encryption key: %s\n", mnemonic);
        printf("\n");
        printf("Please make sure to backup this key in a safe location. " \
               "If the key is lost, the data uploaded will also be lost.\n\n");

        user_options_t *user_opts = req->handle;

        user_opts->mnemonic = mnemonic;
        import_keys(user_opts);

        if (mnemonic) {
            free(mnemonic);
        }
        if (user_opts->pass) {
            free(user_opts->pass);
        }
        if (user_opts->user) {
            free(user_opts->user);
        }
        if (user_opts->host) {
            free(user_opts->host);
        }
    }

    json_object_put(req->response);
    json_object_put(req->body);
    free(req);
    free(work_req);
}

static void list_files_callback(uv_work_t *work_req, int status)
{
    int ret_status = 0;
    assert(status == 0);
    list_files_request_t *req = work_req->data;

    if (req->status_code == 404) {
        printf("Bucket id [%s] does not exist\n", req->bucket_id);
        goto cleanup;
    } else if (req->status_code == 400) {
        printf("Bucket id [%s] is invalid\n", req->bucket_id);
        goto cleanup;
    } else if (req->status_code == 401) {
        printf("Invalid user credentials.\n");
        goto cleanup;
    } else if (req->status_code != 200) {
        printf("Request failed with status code: %i\n", req->status_code);
    }

    if (req->total_files == 0) {
        printf("No files for bucket.\n");
    }

    for (int i = 0; i < req->total_files; i++) {

        storj_file_meta_t *file = &req->files[i];

        printf("ID: %s \tSize: %" PRIu64 " bytes \tDecrypted: %s \tType: %s \tCreated: %s \tName: %s\n",
               file->id,
               file->size,
               file->decrypted ? "true" : "false",
               file->mimetype,
               file->created,
               file->filename);
    }

cleanup:
    json_object_put(req->response);
    storj_free_list_files_request(req);
    free(work_req);
    exit(ret_status);
}

static void delete_file_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    if (req->status_code == 200 || req->status_code == 204) {
        printf("File was successfully removed from bucket.\n");
    } else if (req->status_code == 401) {
        printf("Invalid user credentials.\n");
    } else {
        printf("Failed to remove file from bucket. (%i)\n", req->status_code);
    }

    json_object_put(req->response);
    free(req->path);
    free(req);
    free(work_req);
}

static void delete_bucket_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    if (req->status_code == 200 || req->status_code == 204) {
        printf("Bucket was successfully removed.\n");
    } else if (req->status_code == 401) {
        printf("Invalid user credentials.\n");
    } else {
        printf("Failed to destroy bucket. (%i)\n", req->status_code);
    }

    json_object_put(req->response);
    free(req->path);
    free(req);
    free(work_req);
}

static void get_buckets_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    get_buckets_request_t *req = work_req->data;

    if (req->status_code == 401) {
       printf("Invalid user credentials.\n");
    } else if (req->status_code != 200 && req->status_code != 304) {
        printf("Request failed with status code: %i\n", req->status_code);
    } else if (req->total_buckets == 0) {
        printf("No buckets.\n");
    }

    for (int i = 0; i < req->total_buckets; i++) {
        storj_bucket_meta_t *bucket = &req->buckets[i];
        printf("ID: %s \tDecrypted: %s \tCreated: %s \tName: %s\n",
               bucket->id, bucket->decrypted ? "true" : "false",
               bucket->created, bucket->name);
    }

    json_object_put(req->response);
    storj_free_get_buckets_request(req);
    free(work_req);
}

static void create_bucket_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    create_bucket_request_t *req = work_req->data;

    if (req->status_code == 404) {
        printf("Cannot create bucket [%s]. Name already exists \n", req->bucket->name);
        goto clean_variables;
    } else if (req->status_code == 401) {
        printf("Invalid user credentials.\n");
        goto clean_variables;
    }

    if (req->status_code != 201) {
        printf("Request failed with status code: %i\n", req->status_code);
        goto clean_variables;
    }

    if (req->bucket != NULL) {
        printf("ID: %s \tDecrypted: %s \tName: %s\n",
               req->bucket->id,
               req->bucket->decrypted ? "true" : "false",
               req->bucket->name);
    } else {
        printf("Failed to add bucket.\n");
    }

clean_variables:
    json_object_put(req->response);
    free((char *)req->encrypted_bucket_name);
    free(req->bucket);
    free(req);
    free(work_req);
}

static void get_info_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    if (req->error_code || req->response == NULL) {
        free(req);
        free(work_req);
        if (req->error_code) {
            printf("Request failed, reason: %s\n",
                   curl_easy_strerror(req->error_code));
        } else {
            printf("Failed to get info.\n");
        }
        exit(1);
    }

    struct json_object *info;
    json_object_object_get_ex(req->response, "info", &info);

    struct json_object *title;
    json_object_object_get_ex(info, "title", &title);
    struct json_object *description;
    json_object_object_get_ex(info, "description", &description);
    struct json_object *version;
    json_object_object_get_ex(info, "version", &version);
    struct json_object *host;
    json_object_object_get_ex(req->response, "host", &host);

    printf("Title:       %s\n", json_object_get_string(title));
    printf("Description: %s\n", json_object_get_string(description));
    printf("Version:     %s\n", json_object_get_string(version));
    printf("Host:        %s\n", json_object_get_string(host));

    json_object_put(req->response);
    free(req);
    free(work_req);
}

static int export_keys(char *host)
{
    int status = 0;
    char *user_file = NULL;
    char *root_dir = NULL;
    char *user = NULL;
    char *pass = NULL;
    char *mnemonic = NULL;
    char *key = NULL;

    if (get_user_auth_location(host, &root_dir, &user_file)) {
        printf("Unable to determine user auth filepath.\n");
        status = 1;
        goto clear_variables;
    }

    if (access(user_file, F_OK) != -1) {
        key = calloc(BUFSIZ, sizeof(char));
        printf("Unlock passphrase: ");
        get_password(key, '*');
        printf("\n\n");

        if (storj_decrypt_read_auth(user_file, key, &user, &pass, &mnemonic)) {
            printf("Unable to read user file.\n");
            status = 1;
            goto clear_variables;
        }

        printf("Username:\t%s\nPassword:\t%s\nEncryption key:\t%s\n",
               user, pass, mnemonic);
    }

clear_variables:
    if (user) {
        free(user);
    }
    if (pass) {
        free(pass);
    }
    if (mnemonic) {
        free(mnemonic);
    }
    if (root_dir) {
        free(root_dir);
    }
    if (user_file) {
        free(user_file);
    }
    if (key) {
        free(key);
    }
    return status;
}

int main(int argc, char **argv)
{
    int status = 0;

    static struct option cmd_options[] = {
        {"url", required_argument,  0, 'u'},
        {"version", no_argument,  0, 'v'},
        {"proxy", required_argument,  0, 'p'},
        {"log", required_argument,  0, 'l'},
        {"debug", no_argument,  0, 'd'},
        {"help", no_argument,  0, 'h'},
        {0, 0, 0, 0}
    };

    int index = 0;

    // The default is usually 4 threads, we want to increase to the
    // locally set default value.
#ifdef _WIN32
    if (!getenv("UV_THREADPOOL_SIZE")) {
        _putenv_s("UV_THREADPOOL_SIZE", STORJ_THREADPOOL_SIZE);
    }
#else
    setenv("UV_THREADPOOL_SIZE", STORJ_THREADPOOL_SIZE, 0);
#endif

    char *storj_bridge = getenv("STORJ_BRIDGE");
    int c;
    int log_level = 0;

    char *proxy = getenv("STORJ_PROXY");

    while ((c = getopt_long_only(argc, argv, "hdl:p:vVu:",
                                 cmd_options, &index)) != -1) {
        switch (c) {
            case 'u':
                storj_bridge = optarg;
                break;
            case 'p':
                proxy = optarg;
                break;
            case 'l':
                log_level = atoi(optarg);
                break;
            case 'd':
                log_level = 4;
                break;
            case 'V':
            case 'v':
                printf(CLI_VERSION "\n\n");
                exit(0);
                break;
            case 'h':
                printf(HELP_TEXT);
                exit(0);
                break;
        }
    }

    if (log_level > 4 || log_level < 0) {
        printf("Invalid log level\n");
        return 1;
    }

    int command_index = optind;

    char *command = argv[command_index];
    if (!command) {
        printf(HELP_TEXT);
        return 0;
    }

    if (!storj_bridge) {
        storj_bridge = "https://api.storj.io:443/";
    }

    // Parse the host, part and proto from the storj bridge url
    char proto[6];
    char host[100];
    int port = 0;
    sscanf(storj_bridge, "%5[^://]://%99[^:/]:%99d", proto, host, &port);

    if (port == 0) {
        if (strcmp(proto, "https") == 0) {
            port = 443;
        } else {
            port = 80;
        }
    }

    if (strcmp(command, "login") == 0) {
        printf("'login' is not a storj command. Did you mean 'import-keys'?\n\n");
        return 1;
    }

    if (strcmp(command, "import-keys") == 0) {
        user_options_t user_options = {NULL, NULL, host, NULL, NULL};
        return import_keys(&user_options);
    }

    if (strcmp(command, "export-keys") == 0) {
        return export_keys(host);
    }

    // initialize event loop and environment
    storj_env_t *env = NULL;

    storj_http_options_t http_options = {
        .user_agent = CLI_VERSION,
        .low_speed_limit = STORJ_LOW_SPEED_LIMIT,
        .low_speed_time = STORJ_LOW_SPEED_TIME,
        .timeout = STORJ_HTTP_TIMEOUT
    };

    storj_log_options_t log_options = {
        .logger = json_logger,
        .level = log_level
    };

    if (proxy) {
        http_options.proxy_url = proxy;
    } else {
        http_options.proxy_url = NULL;
    }

    char *user = NULL;
    char *pass = NULL;
    char *mnemonic = NULL;
    char *apikey = NULL;
    char *secretkey = NULL;

    if (strcmp(command, "get-info") == 0) {
        printf("Storj bridge: %s\n\n", storj_bridge);

        storj_bridge_options_t options = {
            .proto = proto,
            .host  = host,
            .port  = port,
            .user  = NULL,
            .pass  = NULL,
            .apikey = NULL,
            .secretkey = NULL
        };

        env = storj_init_env(&options, NULL, &http_options, &log_options);
        if (!env) {
            return 1;
        }

        storj_bridge_get_info(env, NULL, get_info_callback);

    } else if(strcmp(command, "register") == 0) {
        storj_bridge_options_t options = {
            .proto = proto,
            .host  = host,
            .port  = port,
            .user  = NULL,
            .pass  = NULL,
            .apikey = NULL,
            .secretkey = NULL
        };

        env = storj_init_env(&options, NULL, &http_options, &log_options);
        if (!env) {
            return 1;
        }

        user = calloc(BUFSIZ, sizeof(char));
        if (!user) {
            return 1;
        }
        printf("Bridge username (email): ");
        get_input(user);

        printf("Bridge password: ");
        pass = calloc(BUFSIZ, sizeof(char));
        if (!pass) {
            return 1;
        }
        get_password(pass, '*');
        printf("\n");

        user_options_t user_opts = {strdup(user), strdup(pass), strdup(host), NULL, NULL};

        if (!user_opts.user || !user_opts.host || !user_opts.pass) {
            return 1;
        }

        storj_bridge_register(env, user, pass, &user_opts, register_callback);
    } else {

        char *user_file = NULL;
        char *root_dir = NULL;
        if (get_user_auth_location(host, &root_dir, &user_file)) {
            printf("Unable to determine user auth filepath.\n");
            return 1;
        }

        // We aren't using root dir so free it
        free(root_dir);

        // First, get auth from environment variables
        user = getenv("STORJ_BRIDGE_USER") ?
            strdup(getenv("STORJ_BRIDGE_USER")) : NULL;

        pass = getenv("STORJ_BRIDGE_PASS") ?
            strdup(getenv("STORJ_BRIDGE_PASS")) : NULL;

        mnemonic = getenv("STORJ_ENCRYPTION_KEY") ?
            strdup(getenv("STORJ_ENCRYPTION_KEY")) : NULL;
        
        apikey = getenv("GENARO_APIKEY") ?
            strdup(getenv("GENARO_APIKEY")) : NULL;
        
        secretkey = getenv("GENARO_SECRETKEY") ?
            strdup(getenv("GENARO_SECRETKEY")) : NULL;

        char *keypass = getenv("STORJ_KEYPASS");

        // Second, try to get from encrypted user file
        if (( ((!user || !pass) && (!apikey || !secretkey)) || !mnemonic) && access(user_file, F_OK) != -1) {

            char *key = NULL;
            if (keypass) {
                key = calloc(strlen(keypass) + 1, sizeof(char));
                if (!key) {
                    return 1;
                }
                strcpy(key, keypass);
            } else {
                key = calloc(BUFSIZ, sizeof(char));
                if (!key) {
                    return 1;
                }
                printf("Unlock passphrase: ");
                get_password(key, '*');
                printf("\n");
            }
            char *file_user = NULL;
            char *file_pass = NULL;
            char *file_mnemonic = NULL;
            if (storj_decrypt_read_auth(user_file, key, &file_user,
                                        &file_pass, &file_mnemonic)) {
                printf("Unable to read user file. Invalid keypass or path.\n");
                free(key);
                free(user_file);
                free(file_user);
                free(file_pass);
                free(file_mnemonic);
                goto end_program;
            }
            free(key);
            free(user_file);

            if (!user && file_user) {
                user = file_user;
            } else if (file_user) {
                free(file_user);
            }

            if (!pass && file_pass) {
                pass = file_pass;
            } else if (file_pass) {
                free(file_pass);
            }

            if (!mnemonic && file_mnemonic) {
                mnemonic = file_mnemonic;
            } else if (file_mnemonic) {
                free(file_mnemonic);
            }

        }

        // Third, ask for authentication
        if (!user && (!apikey || !secretkey)) {
            char *user_input = malloc(BUFSIZ);
            if (user_input == NULL) {
                return 1;
            }
            printf("Bridge username (email): ");
            get_input(user_input);
            int num_chars = strlen(user_input);
            user = calloc(num_chars + 1, sizeof(char));
            if (!user) {
                return 1;
            }
            memcpy(user, user_input, num_chars);
            free(user_input);
        }

        if (!pass && (!apikey || !secretkey)) {
            printf("Bridge password: ");
            pass = calloc(BUFSIZ, sizeof(char));
            if (!pass) {
                return 1;
            }
            get_password(pass, '*');
            printf("\n");
        }

        if (!mnemonic) {
            printf("Encryption key: ");
            char *mnemonic_input = malloc(BUFSIZ);
            if (mnemonic_input == NULL) {
                return 1;
            }
            get_input(mnemonic_input);
            int num_chars = strlen(mnemonic_input);
            mnemonic = calloc(num_chars + 1, sizeof(char));
            if (!mnemonic) {
                return 1;
            }
            memcpy(mnemonic, mnemonic_input, num_chars);
            free(mnemonic_input);
            printf("\n");
        }

        storj_bridge_options_t options = {
            .proto = proto,
            .host  = host,
            .port  = port,
            .user  = user,
            .pass  = pass,
            .apikey = apikey,
            .secretkey = secretkey
        };

        storj_encrypt_options_t encrypt_options = {
            .mnemonic = mnemonic
        };

        env = storj_init_env(&options, &encrypt_options,
                             &http_options, &log_options);
        if (!env) {
            status = 1;
            goto end_program;
        }

        if (strcmp(command, "download-file") == 0) {
            char *bucket_id = argv[command_index + 1];
            char *file_id = argv[command_index + 2];
            char *path = argv[command_index + 3];

            if (!bucket_id || !file_id || !path) {
                printf("Missing arguments: <bucket-id> <file-id> <path>\n");
                status = 1;
                goto end_program;
            }

            if (download_file(env, bucket_id, file_id, path)) {
                status = 1;
                goto end_program;
            }
        } else if (strcmp(command, "upload-file") == 0) {
            char *bucket_id = argv[command_index + 1];
            char *path = argv[command_index + 2];

            if (!bucket_id || !path) {
                printf("Missing arguments: <bucket-id> <path>\n");
                status = 1;
                goto end_program;
            }

            if (upload_file(env, bucket_id, path)) {
                status = 1;
                goto end_program;
            }
        } else if (strcmp(command, "list-files") == 0) {
            char *bucket_id = argv[command_index + 1];

            if (!bucket_id) {
                printf("Missing first argument: <bucket-id>\n");
                status = 1;
                goto end_program;
            }

            storj_bridge_list_files(env, bucket_id, NULL, list_files_callback);
        } else if (strcmp(command, "add-bucket") == 0) {
            char *bucket_name = argv[command_index + 1];

            if (!bucket_name) {
                printf("Missing first argument: <bucket-name>\n");
                status = 1;
                goto end_program;
            }

            storj_bridge_create_bucket(env, bucket_name,
                                       NULL, create_bucket_callback);

        } else if (strcmp(command, "remove-bucket") == 0) {
            char *bucket_id = argv[command_index + 1];

            if (!bucket_id) {
                printf("Missing first argument: <bucket-id>\n");
                status = 1;
                goto end_program;
            }

            storj_bridge_delete_bucket(env, bucket_id, NULL,
                                       delete_bucket_callback);

        } else if (strcmp(command, "remove-file") == 0) {
            char *bucket_id = argv[command_index + 1];
            char *file_id = argv[command_index + 2];

            if (!bucket_id || !file_id) {
                printf("Missing arguments, expected: <bucket-id> <file-id>\n");
                status = 1;
                goto end_program;
            }
            storj_bridge_delete_file(env, bucket_id, file_id,
                                     NULL, delete_file_callback);

        } else if (strcmp(command, "list-buckets") == 0) {
            storj_bridge_get_buckets(env, NULL, get_buckets_callback);
        } else if (strcmp(command, "list-mirrors") == 0) {
            char *bucket_id = argv[command_index + 1];
            char *file_id = argv[command_index + 2];

            if (!bucket_id || !file_id) {
                printf("Missing arguments, expected: <bucket-id> <file-id>\n");
                status = 1;
                goto end_program;
            }
            storj_bridge_list_mirrors(env, bucket_id, file_id,
                                      NULL, list_mirrors_callback);
        } else {
            printf("'%s' is not a storj command. See 'storj --help'\n\n",
                   command);
            status = 1;
            goto end_program;
        }

    }

    // run all queued events
    if (uv_run(env->loop, UV_RUN_DEFAULT)) {
        uv_loop_close(env->loop);

        // cleanup
        storj_destroy_env(env);

        status = 1;
        goto end_program;
    }

end_program:
    if (env) {
        storj_destroy_env(env);
    }
    if (user) {
        free(user);
    }
    if (pass) {
        free(pass);
    }
    if (mnemonic) {
        free(mnemonic);
    }
    return status;
}
