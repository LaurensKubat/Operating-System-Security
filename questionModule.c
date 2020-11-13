#define PAM_SM_AUTH

#include <stdio.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>


int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {    char questions[5][52] = {
        "What is your name?",
        "What is your quest?",
        "What is your favorite colour?",
        "What is the capital of Assyria?",
        "What is the airspeed velocity of an unladen swallow?",
    };
    
    char answers[5][50] = {
        "My name is Sir Lancelot of Camelot.",
        "To seek the holy grail.",
        "Blue.",
        "Assur.",
        "African or European?",
    };
    int question = rand() % 5;

    printf(questions[question]);
    char answer[50];
    gets(answer);
    if (answers[question] == answer) {
        return(PAM_SUCCESS);
    }
    return (PAM_PERM_DENIED);
}