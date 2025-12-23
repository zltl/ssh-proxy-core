/**
 * @file router.h
 * @brief SSH Proxy Core - Router and Upstream Management
 *
 * Implements routing decisions and upstream connection management.
 * Routes SSH connections based on username, target address, or metadata.
 */

#ifndef SSH_PROXY_ROUTER_H
#define SSH_PROXY_ROUTER_H

#include <stdint.h>
#include <stdbool.h>
#include <libssh/libssh.h>
#include "session.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum number of upstream servers */
#define ROUTER_MAX_UPSTREAMS 64

/* Maximum hostname length */
#define ROUTER_MAX_HOST 256

/* Upstream health status */
typedef enum {
    UPSTREAM_HEALTH_UNKNOWN = 0,
    UPSTREAM_HEALTH_HEALTHY,
    UPSTREAM_HEALTH_UNHEALTHY
} upstream_health_t;

/* Load balancing policy */
typedef enum {
    LB_POLICY_ROUND_ROBIN = 0,  /* Rotate through upstreams */
    LB_POLICY_RANDOM,           /* Random selection */
    LB_POLICY_LEAST_CONN,       /* Least connections */
    LB_POLICY_HASH              /* Hash-based (by username) */
} lb_policy_t;

/* Forward declarations */
typedef struct router router_t;
typedef struct upstream upstream_t;
typedef struct route_rule route_rule_t;

/* Upstream server configuration */
typedef struct upstream_config {
    char host[ROUTER_MAX_HOST];     /* Host address */
    uint16_t port;                  /* Port number */
    int weight;                     /* Load balancing weight */
    bool enabled;                   /* Whether upstream is enabled */
} upstream_config_t;

/* Upstream server state */
struct upstream {
    upstream_config_t config;       /* Configuration */
    upstream_health_t health;       /* Health status */
    size_t active_connections;      /* Current connection count */
    size_t total_connections;       /* Total historical connections */
    time_t last_check;              /* Last health check time */
    time_t last_failure;            /* Last failure time */
    int consecutive_failures;       /* Consecutive failure count */
};

/* Route rule - matches connections to upstreams */
typedef struct route_rule {
    char name[64];                  /* Rule name */
    char match_username[128];       /* Username pattern (glob) */
    char match_target[256];         /* Target pattern (glob) */
    int upstream_index;             /* Index of upstream to use (-1 for default) */
    bool enabled;                   /* Whether rule is enabled */
    route_rule_t *next;             /* Next rule in list */
} route_rule_t;

/* Router configuration */
typedef struct router_config {
    lb_policy_t lb_policy;          /* Load balancing policy */
    uint32_t connect_timeout_ms;    /* Upstream connect timeout */
    uint32_t health_check_interval; /* Health check interval (seconds) */
    int max_retries;                /* Maximum connection retries */
    bool health_check_enabled;      /* Enable health checks */
} router_config_t;

/* Route result */
typedef struct route_result {
    upstream_t *upstream;           /* Selected upstream */
    int upstream_index;             /* Upstream index */
    const char *matched_rule;       /* Name of matched rule (or NULL) */
} route_result_t;

/**
 * @brief Create a new router
 * @param config Router configuration
 * @return Router instance or NULL on error
 */
router_t *router_create(const router_config_t *config);

/**
 * @brief Destroy router
 * @param router Router instance
 */
void router_destroy(router_t *router);

/**
 * @brief Add an upstream server
 * @param router Router instance
 * @param config Upstream configuration
 * @return Upstream index (>= 0) on success, -1 on error
 */
int router_add_upstream(router_t *router, const upstream_config_t *config);

/**
 * @brief Remove an upstream server
 * @param router Router instance
 * @param index Upstream index
 * @return 0 on success, -1 on error
 */
int router_remove_upstream(router_t *router, int index);

/**
 * @brief Get upstream by index
 * @param router Router instance
 * @param index Upstream index
 * @return Upstream or NULL if not found
 */
upstream_t *router_get_upstream(router_t *router, int index);

/**
 * @brief Get number of upstreams
 * @param router Router instance
 * @return Number of upstreams
 */
size_t router_get_upstream_count(const router_t *router);

/**
 * @brief Add a routing rule
 * @param router Router instance
 * @param rule Route rule (copied)
 * @return 0 on success, -1 on error
 */
int router_add_rule(router_t *router, const route_rule_t *rule);

/**
 * @brief Remove a routing rule by name
 * @param router Router instance
 * @param name Rule name
 * @return 0 on success, -1 if not found
 */
int router_remove_rule(router_t *router, const char *name);

/**
 * @brief Resolve route for a session
 * @param router Router instance
 * @param username Username
 * @param target Target address
 * @param result Route result (output)
 * @return 0 on success, -1 if no route found
 */
int router_resolve(router_t *router, const char *username,
                   const char *target, route_result_t *result);

/**
 * @brief Connect to upstream server
 * @param router Router instance
 * @param result Route result from router_resolve
 * @param timeout_ms Connection timeout in milliseconds
 * @return SSH session connected to upstream, or NULL on error
 */
ssh_session router_connect(router_t *router, route_result_t *result,
                           uint32_t timeout_ms);

/**
 * @brief Notify router of connection result
 * @param router Router instance
 * @param upstream_index Upstream index
 * @param success Whether connection succeeded
 */
void router_notify_connect(router_t *router, int upstream_index, bool success);

/**
 * @brief Notify router of connection close
 * @param router Router instance
 * @param upstream_index Upstream index
 */
void router_notify_close(router_t *router, int upstream_index);

/**
 * @brief Run health checks on all upstreams
 * @param router Router instance
 */
void router_health_check(router_t *router);

/**
 * @brief Set default upstream index
 * @param router Router instance
 * @param index Upstream index to use as default
 * @return 0 on success, -1 if index invalid
 */
int router_set_default_upstream(router_t *router, int index);

/**
 * @brief Match a string against a glob pattern
 * @param pattern Glob pattern (supports * and ?)
 * @param str String to match
 * @return true if matches
 */
bool router_glob_match(const char *pattern, const char *str);

#ifdef __cplusplus
}
#endif

#endif /* SSH_PROXY_ROUTER_H */
