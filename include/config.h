/**
 * @file config.h
 * @brief SSH Proxy Core - Configuration Module
 *
 * Loads user credentials, public keys, and user-to-upstream route mappings
 * from configuration files instead of hardcoding.
 */

#ifndef SSH_PROXY_CONFIG_H
#define SSH_PROXY_CONFIG_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum lengths for config values */
#define CONFIG_MAX_USERNAME 128
#define CONFIG_MAX_PASSWORD_HASH 256
#define CONFIG_MAX_PUBKEY 8192
#define CONFIG_MAX_PRIVKEY_PATH 512
#define CONFIG_MAX_HOST 256
#define CONFIG_MAX_LINE 4096

/* User entry in configuration */
typedef struct config_user {
    char username[CONFIG_MAX_USERNAME];
    char password_hash[CONFIG_MAX_PASSWORD_HASH];
    char *pubkeys;                      /* Authorized public keys (OpenSSH format) */
    bool enabled;
    struct config_user *next;
} config_user_t;

/* User to upstream route mapping */
typedef struct config_route {
    char proxy_user[CONFIG_MAX_USERNAME];     /* User connecting to proxy (supports glob) */
    char upstream_host[CONFIG_MAX_HOST];      /* Target upstream host */
    uint16_t upstream_port;                   /* Target upstream port */
    char upstream_user[CONFIG_MAX_USERNAME];  /* User to authenticate as on upstream */
    char privkey_path[CONFIG_MAX_PRIVKEY_PATH]; /* Private key for upstream auth (optional) */
    bool enabled;
    struct config_route *next;
} config_route_t;

/* Main configuration structure */
typedef struct proxy_config {
    /* Server settings */
    char bind_addr[64];
    uint16_t port;
    char host_key_path[CONFIG_MAX_PRIVKEY_PATH];
    
    /* Users */
    config_user_t *users;
    
    /* User to upstream routes */
    config_route_t *routes;
    
    /* Logging */
    int log_level;                      /* 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR */
    char audit_log_dir[256];
    
    /* Limits */
    size_t max_sessions;
    uint32_t session_timeout;
    uint32_t auth_timeout;
} proxy_config_t;

/**
 * @brief Create an empty configuration with default values
 * @return Configuration instance or NULL on error
 */
proxy_config_t *config_create(void);

/**
 * @brief Load configuration from file
 * @param path Path to configuration file
 * @return Configuration instance or NULL on error
 */
proxy_config_t *config_load(const char *path);

/**
 * @brief Destroy configuration and free all memory
 * @param config Configuration instance
 */
void config_destroy(proxy_config_t *config);

/**
 * @brief Add a user to configuration
 * @param config Configuration instance
 * @param username Username
 * @param password_hash Password hash (crypt format)
 * @param pubkeys Authorized public keys (OpenSSH format, can be NULL)
 * @return 0 on success, -1 on error
 */
int config_add_user(proxy_config_t *config,
                    const char *username,
                    const char *password_hash,
                    const char *pubkeys);

/**
 * @brief Find a user by username
 * @param config Configuration instance
 * @param username Username to find
 * @return User entry or NULL if not found
 */
config_user_t *config_find_user(const proxy_config_t *config,
                                const char *username);

/**
 * @brief Add a user to upstream route
 * @param config Configuration instance
 * @param proxy_user User pattern connecting to proxy (supports glob: *, ?)
 * @param upstream_host Target upstream host
 * @param upstream_port Target upstream port
 * @param upstream_user Username for upstream authentication
 * @param privkey_path Path to private key (optional, can be NULL)
 * @return 0 on success, -1 on error
 */
int config_add_route(proxy_config_t *config,
                     const char *proxy_user,
                     const char *upstream_host,
                     uint16_t upstream_port,
                     const char *upstream_user,
                     const char *privkey_path);

/**
 * @brief Find route for a proxy user
 * @param config Configuration instance
 * @param proxy_user Username connecting to proxy
 * @return Route entry or NULL if not found
 */
config_route_t *config_find_route(const proxy_config_t *config,
                                  const char *proxy_user);

/**
 * @brief Reload configuration from file
 * @param config Existing configuration (will be modified)
 * @param path Path to configuration file
 * @return 0 on success, -1 on error
 */
int config_reload(proxy_config_t *config, const char *path);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_CONFIG_H */
