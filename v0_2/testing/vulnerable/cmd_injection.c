#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char command[256];

    if (argc > 1) {
        // PATTERN PERICOLOSO: concatena l'input dell'utente direttamente in un comando di sistema
        sprintf(command, "ping -c 4 %s", argv[1]);
        
        printf("Eseguo il comando: %s\n", command);
        system(command);
    }
    return 0;
}