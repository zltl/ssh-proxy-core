/**
 * @file ssh_proxy.h
 * @brief SSH Proxy Core Library - Main Header
 * @version 1.0.0
 */

#ifndef SSH_PROXY_H
#define SSH_PROXY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <libssh/libssh.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version information */
#define SSH_PROXY_VERSION_MAJOR 1
#define SSH_PROXY_VERSION_MINOR 0
#define SSH_PROXY_VERSION_PATCH 0

/* Error codes */
typedef enum {
    SSH_PROXY_OK = 0,
    SSH_PROXY_ERROR = -1,
    SSH_PROXY_ERROR_NOMEM = -2,
    SSH_PROXY_ERROR_INVALID_ARG = -3,
    SSH_PROXY_ERROR_CONNECTION = -4,
    SSH_PROXY_ERROR_AUTH = -5
} ssh_proxy_error_t;

/* Forward declarations */
typedef struct ssh_proxy ssh_proxy_t;
typedef struct ssh_proxy_config ssh_proxy_config_t;

/**
 * @brief Configuration structure for SSH proxy
 */
struct ssh_proxy_config {
    const char *listen_addr;    /* Address to listen on */
    uint16_t listen_port;       /* Port to listen on */
    const char *target_addr;    /* Target address */
    uint16_t target_port;       /* Target port */
    size_t max_connections;     /* Maximum concurrent connections */
    uint32_t timeout_ms;        /* Connection timeout in milliseconds */
};

/**
 * @brief Get version string
 * @return Version string (e.g., "1.0.0")
 */
const char *ssh_proxy_version(void);

/**
 * @brief Create a new SSH proxy instance
 * @param config Configuration for the proxy
 * @return Pointer to proxy instance, or NULL on error
 */
ssh_proxy_t *ssh_proxy_create(const ssh_proxy_config_t *config);

/**
 * @brief Destroy an SSH proxy instance
 * @param proxy Pointer to proxy instance
 */
void ssh_proxy_destroy(ssh_proxy_t *proxy);

/**
 * @brief Start the SSH proxy
 * @param proxy Pointer to proxy instance
 * @return SSH_PROXY_OK on success, error code on failure
 */
ssh_proxy_error_t ssh_proxy_start(ssh_proxy_t *proxy);

/**
 * @brief Stop the SSH proxy
 * @param proxy Pointer to proxy instance
 * @return SSH_PROXY_OK on success, error code on failure
 */
ssh_proxy_error_t ssh_proxy_stop(ssh_proxy_t *proxy);

/**
 * @brief Check if proxy is running
 * @param proxy Pointer to proxy instance
 * @return true if running, false otherwise
 */
bool ssh_proxy_is_running(const ssh_proxy_t *proxy);

/**
 * @brief Get the last error message
 * @param proxy Pointer to proxy instance
 * @return Error message string
 */
const char *ssh_proxy_get_error(const ssh_proxy_t *proxy);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_H */
