/*
 * Ticket client for the existing one-time PAM redeem.
 * This is not a PAM shared library. It does not call pam_get_authtok and it
 * does not read or store the account password. A host still uses pam_exec.
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#endif

static int ticket_ok(const char *ticket) {
    size_t length = strlen(ticket);
    if (length < 1 || length > 128) return 0;
    for (size_t index = 0; index < length; index++) {
        unsigned char value = (unsigned char)ticket[index];
        if (!isalnum(value) && value != '_' && value != '-') return 0;
    }
    return 1;
}

static int url_ok(const char *url) {
    const char *prefix = "https://";
    size_t prefix_length = strlen(prefix);
    const char *host;
    if (strncmp(url, prefix, prefix_length) != 0) return 0;
    host = url + prefix_length;
    if (*host == '\0' || *host == '/' || *host == ':' || strchr(host, '@') || strchr(host, '?') || strchr(host, '#')) return 0;
    if (strstr(host, "//") != NULL) return 0;
    for (const char *cursor = host; *cursor; cursor++) {
        if (*cursor == ' ' || *cursor == '\\') return 0;
        if (*cursor == '/') return cursor[1] == '\0';
    }
    return 1;
}

static int json_string(const char *json, const char *key, char *out, size_t out_size) {
    char pattern[80];
    const char *found;
    size_t length = 0;
    if (strlen(key) > 40) return 0;
    snprintf(pattern, sizeof pattern, "\"%s\"", key);
    found = strstr(json, pattern);
    if (!found) return 0;
    found += strlen(pattern);
    while (*found == ' ' || *found == '\t' || *found == '\n' || *found == '\r') found++;
    if (*found != ':') return 0;
    found++;
    while (*found == ' ' || *found == '\t' || *found == '\n' || *found == '\r') found++;
    if (*found != '"') return 0;
    found++;
    while (*found && *found != '"') {
        if (*found == '\\' || (unsigned char)*found < 0x20) return 0;
        if (length + 1 >= out_size) return 0;
        out[length++] = *found++;
    }
    if (*found != '"') return 0;
    out[length] = '\0';
    return 1;
}

static int self_test(void) {
    char server[200];
    const char *config = "{\"server\":\"https://investigations.example\",\"resource\":\"linux:ssh\",\"service_key\":\"abcdefghijklmnopqrstuvwxyz012345\"}";
    if (!ticket_ok("abc_DEF-01")) return 1;
    if (ticket_ok("") || ticket_ok("has space") || ticket_ok("bad/ticket")) return 1;
    if (!url_ok("https://investigations.example") || !url_ok("https://investigations.example/")) return 1;
    if (url_ok("http://investigations.example") || url_ok("https://user:secret@investigations.example")) return 1;
    if (!json_string(config, "server", server, sizeof server)) return 1;
    if (strcmp(server, "https://investigations.example") != 0) return 1;
    if (!url_ok(server)) return 1;
    return 0;
}

#ifdef _WIN32
static int redeem(const char *server, const char *resource, const char *key, const char *user, const char *ticket) {
    const char *host = server + strlen("https://");
    wchar_t host_name[256];
    wchar_t headers[400];
    char body[512];
    INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
    HINTERNET session = NULL, connection = NULL, request = NULL;
    BOOL sent, ok;
    DWORD status = 0, status_size = sizeof status;
    char response[256];
    DWORD read = 0;
    int code = 1;
    const char *slash = strchr(host, '/');
    const char *colon = strchr(host, ':');
    char host_ascii[200];
    size_t host_length = slash ? (size_t)(slash - host) : strlen(host);
    if (colon && (!slash || colon < slash)) {
        host_length = (size_t)(colon - host);
        port = (INTERNET_PORT)atoi(colon + 1);
        if (port == 0) return 1;
    }
    if (host_length == 0 || host_length >= sizeof host_ascii) return 1;
    memcpy(host_ascii, host, host_length);
    host_ascii[host_length] = '\0';
    if (mbstowcs(host_name, host_ascii, 255) != host_length) return 1;
    host_name[host_length] = L'\0';
    if (snprintf(body, sizeof body,
                 "{\"username\":\"%s\",\"resource\":\"%s\",\"ticket\":\"%s\"}",
                 user, resource, ticket) >= (int)sizeof body) return 1;
    session = WinHttpOpen(L"zanaq-pam-ticket", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return 1;
    connection = WinHttpConnect(session, host_name, port, 0);
    if (!connection) goto done;
    request = WinHttpOpenRequest(connection, L"POST", L"/api/iam/pam/redeem", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!request) goto done;
    if (swprintf(headers, sizeof headers / sizeof headers[0], L"Content-Type: application/json\r\nX-PAM-Key: %hs\r\n", key) < 0) goto done;
    sent = WinHttpSendRequest(request, headers, (DWORD)-1, body, (DWORD)strlen(body), (DWORD)strlen(body), 0);
    if (!sent || !WinHttpReceiveResponse(request, NULL)) goto done;
    ok = WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX);
    if (!ok || status != 200) goto done;
    if (!WinHttpReadData(request, response, sizeof response - 1, &read)) goto done;
    response[read] = '\0';
    if (strstr(response, "\"authorized\":true") || strstr(response, "\"authorized\": true")) code = 0;
done:
    if (request) WinHttpCloseHandle(request);
    if (connection) WinHttpCloseHandle(connection);
    if (session) WinHttpCloseHandle(session);
    return code;
}
#endif

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) return self_test();
    fprintf(stderr, "pam_ticket redeems one HTTPS ticket and does not read an account password\n");
#ifndef _WIN32
    (void)argc;
    return 1;
#else
    if (argc != 2) return 1;
    const char *pam_type = getenv("PAM_TYPE");
    const char *user = getenv("PAM_USER");
    if (!pam_type || strcmp(pam_type, "auth") != 0 || !user || strlen(user) < 1 || strlen(user) > 120) return 1;
    for (const char *cursor = user; *cursor; cursor++) {
        if (*cursor == '"' || *cursor == '\\' || (unsigned char)*cursor < 0x20) return 1;
    }
    FILE *file = fopen(argv[1], "rb");
    if (!file) return 1;
    char config[1024];
    size_t count = fread(config, 1, sizeof config - 1, file);
    fclose(file);
    config[count] = '\0';
    char server[300], resource[160], key[200], ticket[129];
    if (!json_string(config, "server", server, sizeof server) || !url_ok(server)) return 1;
    if (!json_string(config, "resource", resource, sizeof resource) || strchr(resource, '"')) return 1;
    if (!json_string(config, "service_key", key, sizeof key) || strlen(key) < 32) return 1;
    if (!fgets(ticket, sizeof ticket, stdin)) return 1;
    size_t length = strlen(ticket);
    while (length > 0 && (ticket[length - 1] == '\n' || ticket[length - 1] == '\r' || ticket[length - 1] == '\0')) ticket[--length] = '\0';
    if (!ticket_ok(ticket)) return 1;
    return redeem(server, resource, key, user, ticket);
#endif
}
