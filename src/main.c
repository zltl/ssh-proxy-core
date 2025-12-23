/**
 * @file main.c
 * @brief SSH Proxy Core - Main Entry Point
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "ssh_proxy.h"
#include "ssh_server.h"
#include "session.h"
#include "filter.h"
#include "router.h"
#include "auth_filter.h"
#include "rbac_filter.h"
#include "audit_filter.h"
#include "rate_limit_filter.h"
#include "proxy_handler.h"
#include "logger.h"
#include <pthread.h>

#define DEFAULT_HOST_KEY "/tmp/ssh_proxy_host_key"

static volatile sig_atomic_t g_running = 1;

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static void print_usage(const char *prog_name)
{
    printf("Usage: %s [options]\n", prog_name);
    printf("\nOptions:\n");
    printf("  -h, --help       Show this help message\n");
    printf("  -v, --version    Show version information\n");
    printf("  -d, --debug      Enable debug logging\n");
    printf("  -p, --port PORT  Listen port (default: 2222)\n");
    printf("  -k, --key FILE   Host key file (default: auto-generate)\n");
}

static int ensure_host_key(const char *path)
{
    if (access(path, R_OK) == 0) {
        LOG_DEBUG("Using existing host key: %s", path);
        return 0;
    }

    LOG_INFO("Generating new host key: %s", path);
    return ssh_server_generate_key(path, 4096);
}

int main(int argc, char *argv[])
{
    log_level_t log_level = LOG_LEVEL_INFO;
    uint16_t port = 2222;
    const char *host_key = DEFAULT_HOST_KEY;

    /* Handle command line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("ssh-proxy-core version %s\n", ssh_proxy_version());
            return EXIT_SUCCESS;
        }
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
            log_level = LOG_LEVEL_DEBUG;
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

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    LOG_INFO("SSH Proxy Core v%s starting...", ssh_proxy_version());

    /* Ensure host key exists */
    if (ensure_host_key(host_key) != 0) {
        LOG_FATAL("Failed to prepare host key");
        log_shutdown();
        return EXIT_FAILURE;
    }

    /* Create SSH server configuration */
    ssh_server_config_t server_config = {
        .bind_addr = "0.0.0.0",
        .port = port,
        .host_key_rsa = host_key,
        .host_key_ecdsa = NULL,
        .host_key_ed25519 = NULL,
        .log_verbosity = (log_level <= LOG_LEVEL_DEBUG) ? 1 : 0
    };

    /* Create session manager */
    session_manager_config_t session_config = {
        .max_sessions = 1000,
        .session_timeout = 3600,
        .auth_timeout = 60
    };
    session_manager_t *session_mgr = session_manager_create(&session_config);
    if (session_mgr == NULL) {
        LOG_FATAL("Failed to create session manager");
        log_shutdown();
        return EXIT_FAILURE;
    }

    /* Create filter chain */
    filter_chain_t *filters = filter_chain_create();
    if (filters == NULL) {
        LOG_FATAL("Failed to create filter chain");
        session_manager_destroy(session_mgr);
        log_shutdown();
        return EXIT_FAILURE;
    }

    /* Add rate limit filter */
    rate_limit_filter_config_t rate_cfg = {
        .global_max_connections = 100,
        .global_max_rate = 10,
        .global_interval_sec = 1,
        .log_rejections = true,
        .rules = NULL
    };
    filter_t *rate_filter = rate_limit_filter_create(&rate_cfg);
    if (rate_filter != NULL) {
        filter_chain_add(filters, rate_filter);
    }

    /* Add auth filter with callback (accept all for now) */
    auth_filter_config_t auth_cfg = {
        .backend = AUTH_BACKEND_CALLBACK,
        .allow_password = true,
        .allow_pubkey = true,
        .allow_keyboard = false,
        .max_attempts = 3,
        .timeout_sec = 60,
        .local_users = NULL,
        .password_cb = NULL,  /* Will be set in production */
        .pubkey_cb = NULL,
        .cb_user_data = NULL
    };
    filter_t *auth_filter = auth_filter_create(&auth_cfg);
    if (auth_filter != NULL) {
        filter_chain_add(filters, auth_filter);
    }

    /* Add audit filter */
    audit_filter_config_t audit_cfg = {
        .storage = AUDIT_STORAGE_FILE,
        .log_dir = "/tmp/ssh_proxy_audit",
        .log_prefix = "audit_",
        .record_input = true,
        .record_output = true,
        .record_commands = true,
        .enable_asciicast = true,
        .max_file_size = 0,
        .flush_interval = 5,
        .event_cb = NULL,
        .cb_user_data = NULL
    };
    filter_t *audit_filter = audit_filter_create(&audit_cfg);
    if (audit_filter != NULL) {
        filter_chain_add(filters, audit_filter);
    }

    /* Create router */
    router_config_t router_cfg = {
        .lb_policy = LB_POLICY_ROUND_ROBIN,
        .connect_timeout_ms = 10000,
        .health_check_interval = 30,
        .max_retries = 3,
        .health_check_enabled = false
    };
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
        .host = "127.0.0.1",
        .port = 22,
        .weight = 1,
        .enabled = true
    };
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
    while (g_running && ssh_server_is_running(server)) {
        ssh_session client_ssh = ssh_server_accept(server);
        if (client_ssh == NULL) {
            if (g_running) {
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
        filter_context_t ctx = {
            .session = session,
            .user_data = NULL,
            .username = NULL,
            .password = NULL,
            .pubkey = NULL,
            .pubkey_len = 0,
            .target_host = NULL,
            .target_port = 0
        };

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
    ssh_server_stop(server);
    ssh_server_destroy(server);
    router_destroy(router);
    filter_chain_destroy(filters);
    session_manager_destroy(session_mgr);
    log_shutdown();

    return EXIT_SUCCESS;
}
