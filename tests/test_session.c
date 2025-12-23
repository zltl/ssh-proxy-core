/**
 * @file test_session.c
 * @brief Unit tests for Session Manager
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "session.h"
#include "logger.h"
#include "test_utils.h"

static int test_session_manager_create(void)
{
    TEST_START();

    session_manager_config_t config = {
        .max_sessions = 100,
        .session_timeout = 3600,
        .auth_timeout = 60
    };

    session_manager_t *mgr = session_manager_create(&config);
    ASSERT_NOT_NULL(mgr);
    ASSERT_EQ(session_manager_get_count(mgr), 0);

    session_manager_destroy(mgr);
    TEST_PASS();
}

static int test_session_state_names(void)
{
    TEST_START();

    ASSERT_STR_EQ(session_state_name(SESSION_STATE_NEW), "NEW");
    ASSERT_STR_EQ(session_state_name(SESSION_STATE_HANDSHAKE), "HANDSHAKE");
    ASSERT_STR_EQ(session_state_name(SESSION_STATE_AUTH), "AUTH");
    ASSERT_STR_EQ(session_state_name(SESSION_STATE_AUTHENTICATED), "AUTHENTICATED");
    ASSERT_STR_EQ(session_state_name(SESSION_STATE_ACTIVE), "ACTIVE");
    ASSERT_STR_EQ(session_state_name(SESSION_STATE_CLOSED), "CLOSED");

    TEST_PASS();
}

static int test_session_null_handling(void)
{
    TEST_START();

    /* All functions should handle NULL gracefully */
    ASSERT_EQ(session_get_id(NULL), 0);
    ASSERT_EQ(session_get_state(NULL), SESSION_STATE_CLOSED);
    ASSERT_NULL(session_get_client(NULL));
    ASSERT_NULL(session_get_upstream(NULL));
    ASSERT_NULL(session_get_metadata(NULL));
    ASSERT_NULL(session_get_stats(NULL));
    ASSERT_TRUE(session_is_timeout(NULL, 60));

    session_set_state(NULL, SESSION_STATE_ACTIVE);  /* Should not crash */
    session_touch(NULL);  /* Should not crash */

    ASSERT_NULL(session_manager_create(NULL));

    TEST_PASS();
}

int main(void)
{
    log_init(LOG_LEVEL_WARN, NULL);
    printf("=== Session Manager Tests ===\n\n");

    int failed = 0;
    failed += test_session_manager_create();
    failed += test_session_state_names();
    failed += test_session_null_handling();

    printf("\n");
    if (failed == 0) {
        printf("All tests passed!\n");
    } else {
        printf("%d test(s) failed.\n", failed);
    }

    log_shutdown();
    return failed;
}
