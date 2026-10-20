#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

void set_username(const char *input) {
    char name[16];
    strcpy(name, input);
    printf("user=%s\n", name);
}

void audit(const char *message) {
    syslog(LOG_INFO, message);
}

int lookup_host(const char *host) {
    char cmd[256];
    sprintf(cmd, "nslookup %s", host);
    return system(cmd);
}

void set_username_safe(const char *input) {
    char name[16];
    snprintf(name, sizeof(name), "%s", input);
    printf("user=%s\n", name);
}

int *make_grid(int w, int h) {
    int *g = malloc(w * h * sizeof(int));
    return g;
}
