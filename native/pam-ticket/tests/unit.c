/* Exercise ticket handling with explicit PAM doubles, not a host login stack. */
#include <security/pam_modules.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int pam_set_item(pam_handle_t *p, int item, const void *value) {
    assert(item == PAM_AUTHTOK);
    if (p->set_failure) return PAM_AUTH_ERR;
    const char *text = value;
    assert(!text || strlen(text) < sizeof p->stored);
    strcpy(p->stored, text ? text : "");
    return PAM_SUCCESS;
}
int pam_prompt(pam_handle_t *p, int style, char **response, const char *format, ...) {
    (void)format;
    p->echo_style = style;
    *response = NULL;
    if (p->reply) {
        *response = malloc(strlen(p->reply) + 1);
        assert(*response);
        strcpy(*response, p->reply);
    }
    return p->conversation_result;
}
static void check(const char *reply, int conversation_result, int expected) {
    pam_handle_t p = {0}; p.reply = reply; p.conversation_result = conversation_result;
    strcpy(p.stored, "stale-token");
    assert(pam_sm_authenticate(&p, 0, 0, NULL) == expected);
    assert(p.echo_style == PAM_PROMPT_ECHO_OFF);
    assert(strcmp(p.stored, expected == PAM_IGNORE ? reply : "") == 0);
}
int main(void) {
    check("Abc_def-0123456789012345678901234567890123456", PAM_SUCCESS, PAM_IGNORE);
    check("", PAM_SUCCESS, PAM_AUTH_ERR);
    check("short", PAM_SUCCESS, PAM_AUTH_ERR);
    check("01234567890123456789 bad", PAM_SUCCESS, PAM_AUTH_ERR);
    check("01234567890123456789\n", PAM_SUCCESS, PAM_AUTH_ERR);
    char long_reply[129]; memset(long_reply, 'a', 128); long_reply[128] = 0;
    check(long_reply, PAM_SUCCESS, PAM_AUTH_ERR);
    check(NULL, PAM_AUTH_ERR, PAM_AUTH_ERR);
    check("0123456789012345678901234567890123456789012", PAM_AUTH_ERR, PAM_AUTH_ERR);
    pam_handle_t p = {0}; p.set_failure = 1;
    assert(pam_sm_authenticate(&p, 0, 0, NULL) == PAM_AUTH_ERR);
    assert(pam_sm_setcred(&p, 0, 0, NULL) == PAM_IGNORE);
    puts("10 PAM collector unit checks passed (PAM test doubles)");
    return 0;
}
