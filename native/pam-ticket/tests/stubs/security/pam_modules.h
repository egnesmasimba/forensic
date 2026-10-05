/* Test double declarations only. Production builds use Linux-PAM headers. */
#ifndef FORENSIC_PAM_TEST
#error These headers must only be used by the isolated unit test build
#endif
#ifndef FORENSIC_PAM_STUB_H
#define FORENSIC_PAM_STUB_H
#define PAM_EXTERN extern
#define PAM_SUCCESS 0
#define PAM_AUTH_ERR 7
#define PAM_IGNORE 25
#define PAM_AUTHTOK 6
#define PAM_PROMPT_ECHO_OFF 1
typedef struct pam_handle {
    const char *reply;
    char stored[256];
    int conversation_result;
    int set_failure;
    int echo_style;
} pam_handle_t;
int pam_set_item(pam_handle_t *, int, const void *);
int pam_prompt(pam_handle_t *, int, char **, const char *, ...);
int pam_sm_authenticate(pam_handle_t *, int, int, const char **);
int pam_sm_setcred(pam_handle_t *, int, int, const char **);
#endif
