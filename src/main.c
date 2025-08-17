#include <stdio.h>
#include <stdlib.h>
#include "ssh_proxy.h"

int main(int argc, char *argv[]) {
    // Suppress unused parameter warnings
    (void)argc;
    (void)argv;
    
    printf("SSH Proxy Core - Version 1.0\n");
    printf("Initializing SSH proxy...\n");
    
    // Initialize proxy core
    int result = init_ssh_proxy();
    if (result != 0) {
        fprintf(stderr, "Failed to initialize SSH proxy\n");
        return EXIT_FAILURE;
    }
    
    printf("SSH proxy initialized successfully\n");
    
    // Cleanup
    cleanup_ssh_proxy();
    
    return EXIT_SUCCESS;
}
