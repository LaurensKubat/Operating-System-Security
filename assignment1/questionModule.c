#define PAM_SM_AUTH

#include <stdio.h>
#include <math.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>


int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {    char questions[5][52] = {
        "What is your name?\n",
        "What is your quest?\n",
        "What is your favorite colour?\n",
        "What is the capital of Assyria?\n",
        "What is the airspeed velocity of an unladen swallow?\n",
    };
    
    char answers[5][50] = {
        "My name is Sir Lancelot of Camelot.",
        "To seek the holy grail.",
        "Blue.",
        "Assur.",
        "African or European?",
    };
    int question = rand() % 5;

    puts(questions[question]);
    char answer[50];
    gets(answer);
    if (answers[question] == answer) {
        return(PAM_SUCCESS);
    }
    return (PAM_PERM_DENIED);
}