#include <stdio.h>
#include <string.h>

void vulnerable_function(char *str) {
    char buffer[64];
    
    strcpy(buffer, str); 
    printf("Input ricevuto: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    return 0;
}