#ifndef SSH_PROXY_H
#define SSH_PROXY_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the SSH proxy core
 * @return 0 on success, non-zero on failure
 */
int init_ssh_proxy(void);

/**
 * @brief Clean up SSH proxy resources
 */
void cleanup_ssh_proxy(void);

/**
 * @brief Check if the proxy is initialized
 * @return 1 if initialized, 0 otherwise
 */
int is_proxy_initialized(void);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_H */
