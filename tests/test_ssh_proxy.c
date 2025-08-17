#include <stdio.h>
#include <assert.h>
#include "ssh_proxy.h"

void test_ssh_proxy_init(void) {
    printf("Testing SSH proxy initialization...\n");
    
    // Test initialization
    int result = init_ssh_proxy();
    assert(result == 0);
    assert(is_proxy_initialized() == 1);
    
    // Test double initialization
    result = init_ssh_proxy();
    assert(result == 0); // Should handle gracefully
    
    printf("✓ SSH proxy initialization tests passed\n");
}

void test_ssh_proxy_cleanup(void) {
    printf("Testing SSH proxy cleanup...\n");
    
    // Ensure initialized first
    init_ssh_proxy();
    assert(is_proxy_initialized() == 1);
    
    // Test cleanup
    cleanup_ssh_proxy();
    assert(is_proxy_initialized() == 0);
    
    // Test double cleanup (should be safe)
    cleanup_ssh_proxy();
    assert(is_proxy_initialized() == 0);
    
    printf("✓ SSH proxy cleanup tests passed\n");
}

int main(void) {
    printf("Running SSH Proxy Core Tests\n");
    printf("============================\n");
    
    test_ssh_proxy_init();
    test_ssh_proxy_cleanup();
    
    printf("\n✓ All tests passed!\n");
    return 0;
}
