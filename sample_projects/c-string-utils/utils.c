/* Intentionally insecure C utility library — for education only */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>

/* Hard-coded API key — visible in the binary and source */
const char *api_key = "c-api-key-plaintext-7a3f9d2e";
const char *db_password = "c-db-pass-insecure-1b5c8e4f";

/* Buffer overflow: strcpy does not check length */
void copy_name(char *dst, const char *src) {
    strcpy(dst, src);
}

/* Format string: user-controlled fmt passed directly to printf */
void log_message(const char *fmt) {
    printf(fmt);
}

/* Command injection: system() with a non-literal command built from input */
void run_command(const char *dir) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ls %s", dir);
    system(cmd);
}

/* Weak hash: MD5 used for a password digest */
void hash_password(const char *password, unsigned char *out) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, password, strlen(password));
    MD5_Final(out, &ctx);
}

/* Integer overflow: untrusted n used directly in malloc */
char *make_buffer(int n) {
    char *buf = malloc(n * sizeof(char));
    return buf;
}

/* Path traversal: fopen with a user-supplied path */
FILE *open_file(const char *name) {
    return fopen(name, "r");
}

/* gets: always dangerous, no length limit */
void read_input(char *buf) {
    gets(buf);
}
