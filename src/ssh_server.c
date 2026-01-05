/**
 * @file ssh_server.c
 * @brief SSH Server - libssh based SSH server implementation
 */

#include "ssh_server.h"
#include "logger.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

/* Internal server structure */
struct ssh_server {
    ssh_server_config_t config;
    ssh_bind sshbind;
    int listen_fd;
    bool running;
    char error_msg[256];
};

/* Set error message */
static void set_error(ssh_server_t *server, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vsnprintf(server->error_msg, sizeof(server->error_msg), fmt, args);
    va_end(args);
}

ssh_server_t *ssh_server_create(const ssh_server_config_t *config)
{
    if (config == NULL) {
        return NULL;
    }

    ssh_server_t *server = calloc(1, sizeof(ssh_server_t));
    if (server == NULL) {
        return NULL;
    }

    /* Copy configuration */
    server->config = *config;
    server->sshbind = NULL;
    server->listen_fd = -1;
    server->running = false;
    server->error_msg[0] = '\0';

    /* Initialize libssh */
    if (ssh_init() != SSH_OK) {
        set_error(server, "Failed to initialize libssh");
        free(server);
        return NULL;
    }

    /* Create SSH bind */
    server->sshbind = ssh_bind_new();
    if (server->sshbind == NULL) {
        set_error(server, "Failed to create SSH bind");
        ssh_finalize();
        free(server);
        return NULL;
    }

    /* Configure bind options */
    ssh_bind_options_set(server->sshbind, SSH_BIND_OPTIONS_BINDADDR,
                         config->bind_addr ? config->bind_addr : "0.0.0.0");
    ssh_bind_options_set(server->sshbind, SSH_BIND_OPTIONS_BINDPORT,
                         &config->port);

    /* Set log verbosity */
    if (config->log_verbosity > 0) {
        ssh_bind_options_set(server->sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY,
                             &config->log_verbosity);
    }

    /* Set host keys */
    if (config->host_key_rsa != NULL) {
        if (ssh_bind_options_set(server->sshbind, SSH_BIND_OPTIONS_HOSTKEY,
                                 config->host_key_rsa) != SSH_OK) {
            LOG_WARN("Failed to set RSA host key: %s", config->host_key_rsa);
        }
    }

    if (config->host_key_ecdsa != NULL) {
        if (ssh_bind_options_set(server->sshbind, SSH_BIND_OPTIONS_HOSTKEY,
                                 config->host_key_ecdsa) != SSH_OK) {
            LOG_WARN("Failed to set ECDSA host key: %s", config->host_key_ecdsa);
        }
    }

    if (config->host_key_ed25519 != NULL) {
        if (ssh_bind_options_set(server->sshbind, SSH_BIND_OPTIONS_HOSTKEY,
                                 config->host_key_ed25519) != SSH_OK) {
            LOG_WARN("Failed to set Ed25519 host key: %s", config->host_key_ed25519);
        }
    }

    LOG_DEBUG("SSH server created, bind_addr=%s, port=%d",
              config->bind_addr ? config->bind_addr : "0.0.0.0",
              config->port);

    return server;
}

void ssh_server_destroy(ssh_server_t *server)
{
    if (server == NULL) {
        return;
    }

    if (server->running) {
        ssh_server_stop(server);
    }

    if (server->sshbind != NULL) {
        ssh_bind_free(server->sshbind);
        server->sshbind = NULL;
    }

    ssh_finalize();
    free(server);

    LOG_DEBUG("SSH server destroyed");
}

int ssh_server_start(ssh_server_t *server)
{
    if (server == NULL) {
        return -1;
    }

    if (server->running) {
        set_error(server, "Server is already running");
        return -1;
    }

    /* Bind to port */
    if (ssh_bind_listen(server->sshbind) < 0) {
        set_error(server, "Failed to listen: %s",
                  ssh_get_error(server->sshbind));
        LOG_ERROR("SSH bind listen failed: %s", ssh_get_error(server->sshbind));
        return -1;
    }

    server->running = true;
    LOG_INFO("SSH server listening on %s:%d",
             server->config.bind_addr ? server->config.bind_addr : "0.0.0.0",
             server->config.port);

    return 0;
}

void ssh_server_stop(ssh_server_t *server)
{
    if (server == NULL) {
        return;
    }

    server->running = false;
    
    /* Close the listening socket to interrupt any blocking accept() */
    if (server->sshbind != NULL) {
        socket_t fd = ssh_bind_get_fd(server->sshbind);
        if (fd >= 0) {
            shutdown(fd, SHUT_RDWR);
        }
    }
}

ssh_session ssh_server_accept(ssh_server_t *server)
{
    if (server == NULL || !server->running) {
        return NULL;
    }

    /* Get the listening socket fd */
    socket_t listen_fd = ssh_bind_get_fd(server->sshbind);
    if (listen_fd < 0) {
        set_error(server, "Failed to get bind fd");
        return NULL;
    }
    
    /* Use poll to wait for connection with timeout */
    struct pollfd pfd;
    pfd.fd = listen_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    
    int poll_result = poll(&pfd, 1, 500);  /* 500ms timeout */
    
    if (poll_result < 0) {
        /* Signal interrupted - check running flag */
        if (errno == EINTR) {
            return NULL;
        }
        set_error(server, "poll failed: %s", strerror(errno));
        return NULL;
    }
    
    if (poll_result == 0) {
        /* Timeout - just return to check running flag */
        return NULL;
    }
    
    if (!server->running) {
        return NULL;
    }

    /* Create new session for incoming connection */
    ssh_session session = ssh_new();
    if (session == NULL) {
        set_error(server, "Failed to create SSH session");
        return NULL;
    }

    /* Accept connection */
    int rc = ssh_bind_accept(server->sshbind, session);
    if (rc != SSH_OK) {
        /* Check if server is still running - if not, this is expected */
        if (!server->running) {
            ssh_free(session);
            return NULL;
        }
        /* Accept failed - could be timeout, interrupt, or real error */
        ssh_free(session);
        return NULL;
    }

    LOG_DEBUG("Accepted new SSH connection");
    return session;
}

bool ssh_server_is_running(const ssh_server_t *server)
{
    if (server == NULL) {
        return false;
    }
    return server->running;
}

const char *ssh_server_get_error(const ssh_server_t *server)
{
    if (server == NULL) {
        return "Invalid server instance";
    }
    return server->error_msg;
}

int ssh_server_generate_key(const char *path, int bits)
{
    if (path == NULL) {
        return -1;
    }

    if (bits <= 0) {
        bits = 4096;
    }

    ssh_key key = NULL;
    int rc = ssh_pki_generate(SSH_KEYTYPE_RSA, bits, &key);
    if (rc != SSH_OK) {
        LOG_ERROR("Failed to generate RSA key");
        return -1;
    }

    rc = ssh_pki_export_privkey_file(key, NULL, NULL, NULL, path);
    ssh_key_free(key);

    if (rc != SSH_OK) {
        LOG_ERROR("Failed to export private key to %s", path);
        return -1;
    }

    LOG_INFO("Generated %d-bit RSA host key: %s", bits, path);
    return 0;
}
