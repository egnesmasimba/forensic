/* Collect an IAM ticket for the existing pam_exec bridge; never authenticates alone. */
#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdlib.h>
#include <string.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags; (void)argc; (void)argv;
    /* A failed conversation must not leave an earlier token available downstream. */
    if (pam_set_item(pamh, PAM_AUTHTOK, NULL) != PAM_SUCCESS) return PAM_AUTH_ERR;
    char *ticket = NULL;
    int result = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &ticket, "Forensic access ticket: ");
    if (ticket == NULL) return PAM_AUTH_ERR;
    size_t length = strlen(ticket);
    int valid = result == PAM_SUCCESS && length >= 20 && length <= 127;
    for (size_t i=0; i<length; ++i) {
        unsigned char c=(unsigned char)ticket[i];
        if (!((c>='A' && c<='Z') || (c>='a' && c<='z') || (c>='0' && c<='9') || c=='-' || c=='_')) valid=0;
    }
    result = valid ? pam_set_item(pamh, PAM_AUTHTOK, ticket) : PAM_AUTH_ERR;
    volatile unsigned char *wipe=(volatile unsigned char *)ticket;
    for (size_t i=0; i<length; ++i) wipe[i]=0;
    free(ticket);
    /* PAM_IGNORE ensures this collector cannot provide a successful authentication. */
    return result == PAM_SUCCESS ? PAM_IGNORE : PAM_AUTH_ERR;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_IGNORE;
}
