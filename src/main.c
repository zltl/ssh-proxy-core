/**
 * @file main.c
 * @brief SSH Proxy Core - Main Entry Point
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "ssh_proxy.h"
#include "logger.h"

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
    printf("  -h, --help     Show this help message\n");
    printf("  -v, --version  Show version information\n");
    printf("  -d, --debug    Enable debug logging\n");
}

int main(int argc, char *argv[])
{
    log_level_t log_level = LOG_LEVEL_INFO;

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
    }

    /* Initialize logging */
    log_init(log_level, NULL);

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    LOG_INFO("SSH Proxy Core v%s starting...", ssh_proxy_version());

    /* Create default configuration */
    ssh_proxy_config_t config = {
        .listen_addr = "127.0.0.1",
        .listen_port = 2222,
        .target_addr = "127.0.0.1",
        .target_port = 22,
        .max_connections = 100,
        .timeout_ms = 30000
    };

    /* Create proxy instance */
    ssh_proxy_t *proxy = ssh_proxy_create(&config);
    if (proxy == NULL) {
        LOG_FATAL("Failed to create proxy instance");
        log_shutdown();
        return EXIT_FAILURE;
    }

    /* Start proxy */
    ssh_proxy_error_t err = ssh_proxy_start(proxy);
    if (err != SSH_PROXY_OK) {
        LOG_FATAL("Failed to start proxy: %s", ssh_proxy_get_error(proxy));
        ssh_proxy_destroy(proxy);
        log_shutdown();
        return EXIT_FAILURE;
    }

    LOG_INFO("Proxy listening on %s:%d -> %s:%d",
             config.listen_addr, config.listen_port,
             config.target_addr, config.target_port);
    LOG_DEBUG("Max connections: %zu, timeout: %u ms",
              config.max_connections, config.timeout_ms);

    /* Main loop */
    while (g_running && ssh_proxy_is_running(proxy)) {
        /* TODO: Add actual event loop */
        break;  /* For now, just exit */
    }

    /* Cleanup */
    LOG_INFO("Shutting down...");
    ssh_proxy_stop(proxy);
    ssh_proxy_destroy(proxy);
    log_shutdown();

    return EXIT_SUCCESS;
}
