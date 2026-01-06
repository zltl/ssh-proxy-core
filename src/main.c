/**
 * @file main.c
 * @brief SSH Proxy Core - Main Entry Point
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "audit_filter.h"
#include "auth_filter.h"
#include "config.h"
#include "filter.h"
#include "logger.h"
#include "proxy_handler.h"
#include "rate_limit_filter.h"
#include "rbac_filter.h"
#include "router.h"
#include "session.h"
#include "ssh_server.h"
#include <pthread.h>

#define DEFAULT_HOST_KEY "/tmp/ssh_proxy_host_key"
#define DEFAULT_CONFIG_FILE "/etc/ssh-proxy/config.ini"

static proxy_config_t *g_config = NULL;

static void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("\nOptions:\n");
    printf("  -h, --help         Show this help message\n");
    printf("  -v, --version      Show version information\n");
    printf("  -d, --debug        Enable debug logging\n");
    printf("  -c, --config FILE  Configuration file (default: %s)\n", DEFAULT_CONFIG_FILE);
    printf("  -p, --port PORT    Listen port (default: 2222)\n");
    printf("  -k, --key FILE     Host key file (default: auto-generate)\n");
}

static int ensure_host_key(const char *path) {
    if (access(path, R_OK) == 0) {
        LOG_DEBUG("Using existing host key: %s", path);
        return 0;
    }

    LOG_INFO("Generating new host key: %s", path);
    return ssh_server_generate_key(path, 4096);
}

/* Config-based auth callback */
static auth_result_t config_auth_cb(const char *username, const char *password, void *user_data) {
    proxy_config_t *config = (proxy_config_t *)user_data;
    LOG_DEBUG("config_auth_cb called: user='%s', config=%p", username, (void*)config);
    
    if (config == NULL) {
        LOG_WARN("config_auth_cb: config is NULL");
        return AUTH_RESULT_FAILURE;
    }
    
    config_user_t *user = config_find_user(config, username);
    if (user == NULL) {
        LOG_WARN("Auth failed: user '%s' not found in config", username);
        return AUTH_RESULT_FAILURE;
    }
    
    LOG_DEBUG("Found user '%s', hash='%.20s...'", username, user->password_hash);
    
    /* Verify password if hash is set */
    if (user->password_hash[0] != '\0') {
        if (auth_filter_verify_password(password, user->password_hash)) {
            LOG_INFO("Config auth success for user '%s'", username);
            return AUTH_RESULT_SUCCESS;
        }
        LOG_DEBUG("Password verification failed for user '%s'", username);
    }
    
    LOG_WARN("Auth failed for user '%s': bad password", username);
    return AUTH_RESULT_FAILURE;
}

/* Fallback auth callback for testing (when no config) */
static auth_result_t test_auth_cb(const char *username, const char *password, void *user_data) {
    (void)user_data;
    LOG_INFO("Auth request: user='%s' password='%s'", username, password);
    /* Accept 'test' user with 'test' password */
    if (strcmp(username, "test") == 0 && strcmp(password, "test") == 0) {
        return AUTH_RESULT_SUCCESS;
    }
    return AUTH_RESULT_FAILURE;
}

int main(int argc, char *argv[]) {
    log_level_t log_level = LOG_LEVEL_INFO;
    uint16_t port = 0;  /* 0 means use config or default */
    const char *host_key = NULL;
    const char *config_file = NULL;

    /* Handle command line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("ssh-proxy-core version 1.0.0\n");
            return EXIT_SUCCESS;
        }
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
            log_level = LOG_LEVEL_DEBUG;
        }
        if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) && i + 1 < argc) {
            config_file = argv[++i];
        }
        if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) && i + 1 < argc) {
            port = (uint16_t)atoi(argv[++i]);
        }
        if ((strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) && i + 1 < argc) {
            host_key = argv[++i];
        }
    }

    /* Initialize logging */
    log_init(log_level, NULL);

    /* Note: Signal handling is done via signalfd in ssh_server */

    LOG_INFO("SSH Proxy Core v1.0.0 starting...");

    /* Load configuration file if specified */
    if (config_file != NULL) {
        g_config = config_load(config_file);
        if (g_config == NULL) {
            LOG_FATAL("Failed to load configuration file: %s", config_file);
            log_shutdown();
            return EXIT_FAILURE;
        }
        LOG_INFO("Loaded configuration from %s", config_file);
    } else {
        /* Try default config file, but don't fail if not found */
        if (access(DEFAULT_CONFIG_FILE, R_OK) == 0) {
            g_config = config_load(DEFAULT_CONFIG_FILE);
            if (g_config != NULL) {
                LOG_INFO("Loaded configuration from %s", DEFAULT_CONFIG_FILE);
            }
        }
    }

    /* Apply config values (command line overrides config file) */
    if (port == 0) {
        port = (g_config != NULL) ? g_config->port : 2222;
    }
    if (host_key == NULL) {
        host_key = (g_config != NULL && g_config->host_key_path[0] != '\0') 
                   ? g_config->host_key_path : DEFAULT_HOST_KEY;
    }

    /* Ensure host key exists */
    if (ensure_host_key(host_key) != 0) {
        LOG_FATAL("Failed to prepare host key");
        if (g_config) config_destroy(g_config);
        log_shutdown();
        return EXIT_FAILURE;
    }

    /* Create SSH server configuration */
    ssh_server_config_t server_config = {.bind_addr = (g_config != NULL) ? g_config->bind_addr : "0.0.0.0",
                                         .port = port,
                                         .host_key_rsa = host_key,
                                         .host_key_ecdsa = NULL,
                                         .host_key_ed25519 = NULL,
                                         .log_verbosity = (log_level <= LOG_LEVEL_DEBUG) ? 1 : 0};

    /* Create session manager */
    session_manager_config_t session_config = {
        .max_sessions = (g_config != NULL) ? g_config->max_sessions : 1000,
        .session_timeout = (g_config != NULL) ? g_config->session_timeout : 3600,
        .auth_timeout = (g_config != NULL) ? g_config->auth_timeout : 60};
    session_manager_t *session_mgr = session_manager_create(&session_config);
    if (session_mgr == NULL) {
        LOG_FATAL("Failed to create session manager");
        if (g_config) config_destroy(g_config);
        log_shutdown();
        return EXIT_FAILURE;
    }

    /* Create filter chain */
    filter_chain_t *filters = filter_chain_create();
    if (filters == NULL) {
        LOG_FATAL("Failed to create filter chain");
        session_manager_destroy(session_mgr);
        if (g_config) config_destroy(g_config);
        log_shutdown();
        return EXIT_FAILURE;
    }

    /* Add rate limit filter */
    rate_limit_filter_config_t rate_cfg = {.global_max_connections = 100,
                                           .global_max_rate = 10,
                                           .global_interval_sec = 1,
                                           .log_rejections = true,
                                           .rules = NULL};
    filter_t *rate_filter = rate_limit_filter_create(&rate_cfg);
    if (rate_filter != NULL) {
        filter_chain_add(filters, rate_filter);
    }

    /* Add auth filter - use config-based auth if config loaded, otherwise test callback */
    auth_filter_config_t auth_cfg = {.backend = AUTH_BACKEND_CALLBACK,
                                     .allow_password = true,
                                     .allow_pubkey = true,
                                     .allow_keyboard = false,
                                     .max_attempts = 3,
                                     .timeout_sec = (g_config != NULL) ? g_config->auth_timeout : 60,
                                     .local_users = NULL,
                                     .password_cb = (g_config != NULL) ? config_auth_cb : test_auth_cb,
                                     .pubkey_cb = NULL,
                                     .cb_user_data = g_config};
    filter_t *auth_filter = auth_filter_create(&auth_cfg);
    if (auth_filter != NULL) {
        filter_chain_add(filters, auth_filter);
    }

    /* Add audit filter */
    audit_filter_config_t audit_cfg = {.storage = AUDIT_STORAGE_FILE,
                                       .log_dir = (g_config != NULL && g_config->audit_log_dir[0] != '\0') 
                                                  ? g_config->audit_log_dir : "/tmp/ssh_proxy_audit",
                                       .log_prefix = "audit_",
                                       .record_input = true,
                                       .record_output = true,
                                       .record_commands = true,
                                       .enable_asciicast = true,
                                       .max_file_size = 0,
                                       .flush_interval = 5,
                                       .event_cb = NULL,
                                       .cb_user_data = NULL};
    filter_t *audit_filter = audit_filter_create(&audit_cfg);
    if (audit_filter != NULL) {
        filter_chain_add(filters, audit_filter);
    }

    /* Create router */
    router_config_t router_cfg = {.lb_policy = LB_POLICY_ROUND_ROBIN,
                                  .connect_timeout_ms = 10000,
                                  .health_check_interval = 30,
                                  .max_retries = 3,
                                  .health_check_enabled = false};
    router_t *router = router_create(&router_cfg);
    if (router == NULL) {
        LOG_FATAL("Failed to create router");
        filter_chain_destroy(filters);
        session_manager_destroy(session_mgr);
        log_shutdown();
        return EXIT_FAILURE;
    }

    /* Add default upstream (localhost:22 for testing) */
    upstream_config_t upstream_cfg = {
        .host = "127.0.0.1", .port = 22, .weight = 1, .enabled = true};
    strncpy(upstream_cfg.host, "127.0.0.1", ROUTER_MAX_HOST - 1);
    router_add_upstream(router, &upstream_cfg);

    LOG_INFO("Initialized: session_mgr, %zu filters, router with %zu upstreams",
             filter_chain_count(filters), router_get_upstream_count(router));

    /* Create SSH server */
    ssh_server_t *server = ssh_server_create(&server_config);
    if (server == NULL) {
        LOG_FATAL("Failed to create SSH server");
        router_destroy(router);
        filter_chain_destroy(filters);
        session_manager_destroy(session_mgr);
        log_shutdown();
        return EXIT_FAILURE;
    }

    /* Start SSH server */
    if (ssh_server_start(server) != 0) {
        LOG_FATAL("Failed to start SSH server: %s", ssh_server_get_error(server));
        ssh_server_destroy(server);
        router_destroy(router);
        filter_chain_destroy(filters);
        session_manager_destroy(session_mgr);
        log_shutdown();
        return EXIT_FAILURE;
    }

    LOG_INFO("SSH server ready, waiting for connections...");
    LOG_INFO("Press Ctrl+C to stop");

    /* Main loop - accept connections */
    while (ssh_server_is_running(server)) {
        ssh_session client_ssh = ssh_server_accept(server);
        if (client_ssh == NULL) {
            /* NULL means signal received or error - check if still running */
            if (ssh_server_is_running(server)) {
                /* Periodically cleanup timed-out sessions */
                session_manager_cleanup(session_mgr);
            }
            continue;
        }

        LOG_INFO("New connection accepted");

        /* Create session */
        session_t *session = session_manager_create_session(session_mgr, client_ssh);
        if (session == NULL) {
            LOG_WARN("Failed to create session (limit reached?)");
            ssh_disconnect(client_ssh);
            ssh_free(client_ssh);
            continue;
        }

        session_set_state(session, SESSION_STATE_HANDSHAKE);

        /* Run filter chain on connect */
        filter_context_t ctx = {.session = session,
                                .user_data = NULL,
                                .username = NULL,
                                .password = NULL,
                                .pubkey = NULL,
                                .pubkey_len = 0,
                                .target_host = NULL,
                                .target_port = 0};

        filter_status_t status = filter_chain_on_connect(filters, &ctx);
        if (status == FILTER_REJECT) {
            LOG_WARN("Connection rejected by filter");
            session_manager_remove_session(session_mgr, session);
            continue;
        }

        /* Spawn thread for proxy handler */
        proxy_handler_context_t *handler_ctx = malloc(sizeof(proxy_handler_context_t));
        if (handler_ctx == NULL) {
            LOG_ERROR("Failed to allocate handler context");
            session_manager_remove_session(session_mgr, session);
            continue;
        }

        handler_ctx->session_mgr = session_mgr;
        handler_ctx->filters = filters;
        handler_ctx->router = router;
        handler_ctx->session = session;
        handler_ctx->config = g_config;

        pthread_t thread;
        if (pthread_create(&thread, NULL, proxy_handler_run, handler_ctx) != 0) {
            LOG_ERROR("Failed to create proxy thread");
            free(handler_ctx);
            session_manager_remove_session(session_mgr, session);
            continue;
        }
        pthread_detach(thread);
    }

    /* Cleanup */
    LOG_INFO("Shutting down...");
    
    /* Server already stopped by signal handler via signalfd */
    
    /* Wait for active sessions to close gracefully using nanosleep */
    if (session_manager_get_count(session_mgr) > 0) {
        LOG_DEBUG("Waiting for %zu active sessions to close...", 
                  session_manager_get_count(session_mgr));
        
        struct timespec wait_time = {0, 100000000};  /* 100ms */
        int wait_count = 0;
        const int max_wait = 30;  /* Maximum 3 seconds */
        
        while (session_manager_get_count(session_mgr) > 0 && wait_count < max_wait) {
            nanosleep(&wait_time, NULL);
            session_manager_cleanup(session_mgr);
            wait_count++;
        }
        
        if (session_manager_get_count(session_mgr) > 0) {
            LOG_WARN("Forcing shutdown with %zu active sessions",
                     session_manager_get_count(session_mgr));
        }
    }
    
    ssh_server_destroy(server);
    router_destroy(router);
    filter_chain_destroy(filters);
    session_manager_destroy(session_mgr);
    if (g_config != NULL) {
        config_destroy(g_config);
    }
    log_shutdown();

    return EXIT_SUCCESS;
}
