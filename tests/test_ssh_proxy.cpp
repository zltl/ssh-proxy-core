#include <gtest/gtest.h>
extern "C" {
#include "ssh_proxy.h"
}

class SshProxyTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Clean up before each test
        cleanup_ssh_proxy();
    }
    
    void TearDown() override {
        // Clean up after each test
        cleanup_ssh_proxy();
    }
};

TEST_F(SshProxyTest, InitializationSuccess) {
    // Test initialization
    int result = init_ssh_proxy();
    EXPECT_EQ(result, 0);
    EXPECT_EQ(is_proxy_initialized(), 1);
}

TEST_F(SshProxyTest, DoubleInitialization) {
    // Test double initialization
    int result = init_ssh_proxy();
    EXPECT_EQ(result, 0);
    
    result = init_ssh_proxy();
    EXPECT_EQ(result, 0); // Should handle gracefully
    EXPECT_EQ(is_proxy_initialized(), 1);
}

TEST_F(SshProxyTest, CleanupAfterInit) {
    // Ensure initialized first
    init_ssh_proxy();
    EXPECT_EQ(is_proxy_initialized(), 1);
    
    // Test cleanup
    cleanup_ssh_proxy();
    EXPECT_EQ(is_proxy_initialized(), 0);
}

TEST_F(SshProxyTest, DoubleCleanup) {
    // Initialize first
    init_ssh_proxy();
    EXPECT_EQ(is_proxy_initialized(), 1);
    
    // Test cleanup
    cleanup_ssh_proxy();
    EXPECT_EQ(is_proxy_initialized(), 0);
    
    // Test double cleanup (should be safe)
    cleanup_ssh_proxy();
    EXPECT_EQ(is_proxy_initialized(), 0);
}

TEST_F(SshProxyTest, InitialStateIsUninitialized) {
    // Test that initial state is uninitialized
    EXPECT_EQ(is_proxy_initialized(), 0);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
