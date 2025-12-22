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
#include "logger.h"

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

    /* Create SSH server */
    ssh_server_t *server = ssh_server_create(&server_config);
    if (server == NULL) {
        LOG_FATAL("Failed to create SSH server");
        log_shutdown();
        return EXIT_FAILURE;
    }

    /* Start SSH server */
    if (ssh_server_start(server) != 0) {
        LOG_FATAL("Failed to start SSH server: %s", ssh_server_get_error(server));
        ssh_server_destroy(server);
        log_shutdown();
        return EXIT_FAILURE;
    }

    LOG_INFO("SSH server ready, waiting for connections...");
    LOG_INFO("Press Ctrl+C to stop");

    /* Main loop - accept connections */
    while (g_running && ssh_server_is_running(server)) {
        ssh_session session = ssh_server_accept(server);
        if (session == NULL) {
            if (g_running) {
                LOG_DEBUG("Accept returned NULL, continuing...");
            }
            continue;
        }

        LOG_INFO("New connection accepted");

        /* TODO: Handle SSH handshake and forward to target */
        /* For now, just close the connection */
        ssh_disconnect(session);
        ssh_free(session);
    }

    /* Cleanup */
    LOG_INFO("Shutting down...");
    ssh_server_stop(server);
    ssh_server_destroy(server);
    log_shutdown();

    return EXIT_SUCCESS;
}
