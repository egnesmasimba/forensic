/* Real libpam conversation and pam_exec handoff in a private service directory. */
#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int converse(int count, const struct pam_message **messages,
                    struct pam_response **responses, void *data) {
    struct pam_response *reply = calloc((size_t)count, sizeof(*reply));
    if (!reply) return PAM_BUF_ERR;
    for (int i = 0; i < count; ++i) {
        if (messages[i]->msg_style != PAM_PROMPT_ECHO_OFF) {
            for (int j = 0; j < i; ++j) free(reply[j].resp);
            free(reply);
            return PAM_CONV_ERR;
        }
        reply[i].resp = strdup((const char *)data);
        if (!reply[i].resp) {
            for (int j = 0; j < i; ++j) free(reply[j].resp);
            free(reply);
            return PAM_BUF_ERR;
        }
    }
    *responses = reply;
    return PAM_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc == 3) {
        char ticket[128];
        if (!fgets(ticket, sizeof(ticket), stdin)) return 2;
        ticket[strcspn(ticket, "\r\n")] = 0;
        struct pam_conv conversation = {converse, ticket};
        pam_handle_t *handle = NULL;
        int result = pam_start_confdir("forensic-test", argv[2], &conversation,
                                      argv[1], &handle);
        if (result != PAM_SUCCESS) return 2;
        result = pam_authenticate(handle, 0);
        pam_end(handle, result);
        volatile char *wipe = ticket;
        for (size_t i = 0; i < sizeof(ticket); ++i) wipe[i] = 0;
        return result == PAM_SUCCESS ? 0 : 1;
    }
    if (argc != 2) return 2;
    const char *tickets[] = {"01234567890123456789", "short",
                            "01234567890123456789 bad", "abcdefghijklmnopqrst"};
    for (size_t i = 0; i < sizeof(tickets) / sizeof(tickets[0]); ++i) {
        struct pam_conv conversation = {converse, (void *)tickets[i]};
        pam_handle_t *handle = NULL;
        int result = pam_start_confdir("forensic-test", "test-user", &conversation,
                                      argv[1], &handle);
        if (result != PAM_SUCCESS) return 1;
        result = pam_authenticate(handle, 0);
        int expected_success = i == 0;
        int ok = (result == PAM_SUCCESS) == expected_success;
        pam_end(handle, result);
        if (!ok) {
            fprintf(stderr, "PAM stack scenario %zu failed\n", i);
            return 1;
        }
    }
    puts("4 real Linux PAM collector/pam_exec handoff checks passed");
    return 0;
}
