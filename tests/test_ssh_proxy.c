/**
 * @file test_ssh_proxy.c
 * @brief SSH Proxy Core - Unit Tests
 */

#include "test_utils.h"
#include "ssh_proxy.h"

/* Test: Version string */
static int test_version(void)
{
    const char *version = ssh_proxy_version();
    TEST_ASSERT_NOT_NULL(version, "Version should not be NULL");
    TEST_ASSERT(strlen(version) > 0, "Version should not be empty");
    TEST_ASSERT_STR_EQ(version, "1.0.0", "Version should be 1.0.0");
    return 0;
}

/* Test: Create and destroy proxy */
static int test_create_destroy(void)
{
    ssh_proxy_config_t config = {
        .listen_addr = "127.0.0.1",
        .listen_port = 2222,
        .target_addr = "127.0.0.1",
        .target_port = 22,
        .max_connections = 100,
        .timeout_ms = 30000
    };

    ssh_proxy_t *proxy = ssh_proxy_create(&config);
    TEST_ASSERT_NOT_NULL(proxy, "Proxy should be created");

    ssh_proxy_destroy(proxy);
    return 0;
}

/* Test: Create with NULL config */
static int test_create_null_config(void)
{
    ssh_proxy_t *proxy = ssh_proxy_create(NULL);
    TEST_ASSERT_NULL(proxy, "Proxy should be NULL with NULL config");
    return 0;
}

/* Test: Start and stop proxy */
static int test_start_stop(void)
{
    ssh_proxy_config_t config = {
        .listen_addr = "127.0.0.1",
        .listen_port = 2222,
        .target_addr = "127.0.0.1",
        .target_port = 22,
        .max_connections = 100,
        .timeout_ms = 30000
    };

    ssh_proxy_t *proxy = ssh_proxy_create(&config);
    TEST_ASSERT_NOT_NULL(proxy, "Proxy should be created");
    TEST_ASSERT(!ssh_proxy_is_running(proxy), "Proxy should not be running initially");

    ssh_proxy_error_t err = ssh_proxy_start(proxy);
    TEST_ASSERT_EQ(err, SSH_PROXY_OK, "Start should return OK");
    TEST_ASSERT(ssh_proxy_is_running(proxy), "Proxy should be running after start");

    err = ssh_proxy_stop(proxy);
    TEST_ASSERT_EQ(err, SSH_PROXY_OK, "Stop should return OK");
    TEST_ASSERT(!ssh_proxy_is_running(proxy), "Proxy should not be running after stop");

    ssh_proxy_destroy(proxy);
    return 0;
}

/* Test: Double start should fail */
static int test_double_start(void)
{
    ssh_proxy_config_t config = {
        .listen_addr = "127.0.0.1",
        .listen_port = 2222,
        .target_addr = "127.0.0.1",
        .target_port = 22,
        .max_connections = 100,
        .timeout_ms = 30000
    };

    ssh_proxy_t *proxy = ssh_proxy_create(&config);
    TEST_ASSERT_NOT_NULL(proxy, "Proxy should be created");

    ssh_proxy_error_t err = ssh_proxy_start(proxy);
    TEST_ASSERT_EQ(err, SSH_PROXY_OK, "First start should succeed");

    err = ssh_proxy_start(proxy);
    TEST_ASSERT_NE(err, SSH_PROXY_OK, "Double start should fail");

    ssh_proxy_destroy(proxy);
    return 0;
}

/* Test: Operations with NULL proxy */
static int test_null_operations(void)
{
    TEST_ASSERT_EQ(ssh_proxy_start(NULL), SSH_PROXY_ERROR_INVALID_ARG,
                   "Start with NULL should return invalid arg");
    TEST_ASSERT_EQ(ssh_proxy_stop(NULL), SSH_PROXY_ERROR_INVALID_ARG,
                   "Stop with NULL should return invalid arg");
    TEST_ASSERT(!ssh_proxy_is_running(NULL),
                "is_running with NULL should return false");
    TEST_ASSERT_NOT_NULL(ssh_proxy_get_error(NULL),
                         "get_error with NULL should return message");
    return 0;
}

int main(void)
{
    TEST_BEGIN("SSH Proxy Core Tests");

    RUN_TEST(test_version);
    RUN_TEST(test_create_destroy);
    RUN_TEST(test_create_null_config);
    RUN_TEST(test_start_stop);
    RUN_TEST(test_double_start);
    RUN_TEST(test_null_operations);

    TEST_END();
}
