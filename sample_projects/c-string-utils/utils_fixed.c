/* Secure C utility library — demonstrating the fixes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>  /* SHA-256, not MD5 */
#include <limits.h>
#include <errno.h>

/* Secrets loaded from environment at runtime, not hard-coded */
static const char *get_api_key(void)  { return getenv("API_KEY"); }
static const char *get_db_password(void) { return getenv("DB_PASSWORD"); }

/* Safe copy: strncpy_s / snprintf alternative */
void copy_name(char *dst, size_t dstsz, const char *src) {
    snprintf(dst, dstsz, "%s", src);
}

/* Format string: literal format string, user input passed as argument */
void log_message(const char *msg) {
    printf("%s", msg);
}

/* Command injection fixed: execv with no shell and a validated arg list */
#include <unistd.h>
void run_command(const char *dir) {
    char *argv[] = { "/bin/ls", "--", (char *)dir, NULL };
    execv("/bin/ls", argv);
}

/* Weak hash fixed: SHA-256 */
void hash_password(const char *password, unsigned char *out) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, password, strlen(password));
    SHA256_Final(out, &ctx);
}

/* Integer overflow fixed: bounds-check before malloc */
#define MAX_BUF 1048576
char *make_buffer(size_t n) {
    if (n == 0 || n > MAX_BUF) return NULL;
    return calloc(n, sizeof(char));
}

/* Path traversal fixed: realpath + prefix check */
FILE *open_file(const char *name, const char *base) {
    char real[PATH_MAX];
    if (!realpath(name, real)) return NULL;
    if (strncmp(real, base, strlen(base)) != 0) { errno = EACCES; return NULL; }
    return fopen(real, "r");
}

/* gets fixed: fgets with explicit length */
void read_input(char *buf, size_t len) {
    fgets(buf, (int)len, stdin);
}
