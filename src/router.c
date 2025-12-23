/**
 * @file router.c
 * @brief SSH Proxy Core - Router and Upstream Implementation
 */

#include "router.h"
#include "logger.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Router structure */
struct router {
    router_config_t config;
    upstream_t upstreams[ROUTER_MAX_UPSTREAMS];
    size_t upstream_count;
    route_rule_t *rules;
    int default_upstream;
    size_t round_robin_index;   /* For round-robin LB */
};

/* Simple glob pattern matching */
bool router_glob_match(const char *pattern, const char *str)
{
    if (pattern == NULL || str == NULL) {
        return false;
    }

    while (*pattern && *str) {
        if (*pattern == '*') {
            /* Skip consecutive stars */
            while (*pattern == '*') {
                pattern++;
            }
            if (*pattern == '\0') {
                return true;
            }
            /* Try to match rest of pattern */
            while (*str) {
                if (router_glob_match(pattern, str)) {
                    return true;
                }
                str++;
            }
            return false;
        } else if (*pattern == '?' || *pattern == *str) {
            pattern++;
            str++;
        } else {
            return false;
        }
    }

    /* Handle trailing stars */
    while (*pattern == '*') {
        pattern++;
    }

    return (*pattern == '\0' && *str == '\0');
}

router_t *router_create(const router_config_t *config)
{
    if (config == NULL) {
        return NULL;
    }

    router_t *router = calloc(1, sizeof(router_t));
    if (router == NULL) {
        return NULL;
    }

    router->config = *config;
    router->upstream_count = 0;
    router->rules = NULL;
    router->default_upstream = -1;
    router->round_robin_index = 0;

    LOG_DEBUG("Router created, lb_policy=%d", config->lb_policy);
    return router;
}

void router_destroy(router_t *router)
{
    if (router == NULL) {
        return;
    }

    /* Free rules */
    route_rule_t *rule = router->rules;
    while (rule != NULL) {
        route_rule_t *next = rule->next;
        free(rule);
        rule = next;
    }

    free(router);
    LOG_DEBUG("Router destroyed");
}

int router_add_upstream(router_t *router, const upstream_config_t *config)
{
    if (router == NULL || config == NULL) {
        return -1;
    }

    if (router->upstream_count >= ROUTER_MAX_UPSTREAMS) {
        LOG_ERROR("Maximum upstreams reached (%d)", ROUTER_MAX_UPSTREAMS);
        return -1;
    }

    int index = (int)router->upstream_count;
    upstream_t *upstream = &router->upstreams[index];

    upstream->config = *config;
    upstream->health = UPSTREAM_HEALTH_UNKNOWN;
    upstream->active_connections = 0;
    upstream->total_connections = 0;
    upstream->last_check = 0;
    upstream->last_failure = 0;
    upstream->consecutive_failures = 0;

    router->upstream_count++;

    /* Set as default if first upstream */
    if (router->default_upstream < 0) {
        router->default_upstream = index;
    }

    LOG_INFO("Upstream %d added: %s:%d (weight=%d)",
             index, config->host, config->port, config->weight);

    return index;
}

int router_remove_upstream(router_t *router, int index)
{
    if (router == NULL || index < 0 || (size_t)index >= router->upstream_count) {
        return -1;
    }

    /* Mark as disabled instead of removing to preserve indices */
    router->upstreams[index].config.enabled = false;

    LOG_INFO("Upstream %d disabled: %s:%d",
             index,
             router->upstreams[index].config.host,
             router->upstreams[index].config.port);

    return 0;
}

upstream_t *router_get_upstream(router_t *router, int index)
{
    if (router == NULL || index < 0 || (size_t)index >= router->upstream_count) {
        return NULL;
    }
    return &router->upstreams[index];
}

size_t router_get_upstream_count(const router_t *router)
{
    if (router == NULL) {
        return 0;
    }
    return router->upstream_count;
}

int router_add_rule(router_t *router, const route_rule_t *rule)
{
    if (router == NULL || rule == NULL) {
        return -1;
    }

    route_rule_t *new_rule = calloc(1, sizeof(route_rule_t));
    if (new_rule == NULL) {
        return -1;
    }

    *new_rule = *rule;
    new_rule->next = NULL;

    /* Add to end of list */
    if (router->rules == NULL) {
        router->rules = new_rule;
    } else {
        route_rule_t *last = router->rules;
        while (last->next != NULL) {
            last = last->next;
        }
        last->next = new_rule;
    }

    LOG_DEBUG("Route rule '%s' added: user=%s, target=%s -> upstream=%d",
              rule->name, rule->match_username, rule->match_target,
              rule->upstream_index);

    return 0;
}

int router_remove_rule(router_t *router, const char *name)
{
    if (router == NULL || name == NULL) {
        return -1;
    }

    route_rule_t *prev = NULL;
    route_rule_t *rule = router->rules;

    while (rule != NULL) {
        if (strcmp(rule->name, name) == 0) {
            if (prev == NULL) {
                router->rules = rule->next;
            } else {
                prev->next = rule->next;
            }
            free(rule);
            LOG_DEBUG("Route rule '%s' removed", name);
            return 0;
        }
        prev = rule;
        rule = rule->next;
    }

    return -1;
}

/* Select upstream using load balancing policy */
static int select_upstream_lb(router_t *router, const char *username)
{
    if (router->upstream_count == 0) {
        return -1;
    }

    size_t healthy_count = 0;
    int healthy_indices[ROUTER_MAX_UPSTREAMS];

    /* Find all healthy/enabled upstreams */
    for (size_t i = 0; i < router->upstream_count; i++) {
        upstream_t *u = &router->upstreams[i];
        if (u->config.enabled &&
            u->health != UPSTREAM_HEALTH_UNHEALTHY) {
            healthy_indices[healthy_count++] = (int)i;
        }
    }

    if (healthy_count == 0) {
        /* Fall back to default if all unhealthy */
        if (router->default_upstream >= 0 &&
            router->upstreams[router->default_upstream].config.enabled) {
            return router->default_upstream;
        }
        return -1;
    }

    int selected = -1;

    switch (router->config.lb_policy) {
    case LB_POLICY_ROUND_ROBIN:
        selected = healthy_indices[router->round_robin_index % healthy_count];
        router->round_robin_index++;
        break;

    case LB_POLICY_RANDOM:
        selected = healthy_indices[rand() % healthy_count];
        break;

    case LB_POLICY_LEAST_CONN: {
        size_t min_conn = SIZE_MAX;
        for (size_t i = 0; i < healthy_count; i++) {
            upstream_t *u = &router->upstreams[healthy_indices[i]];
            if (u->active_connections < min_conn) {
                min_conn = u->active_connections;
                selected = healthy_indices[i];
            }
        }
        break;
    }

    case LB_POLICY_HASH:
        if (username != NULL && *username != '\0') {
            /* Simple hash of username */
            unsigned long hash = 5381;
            const char *p = username;
            while (*p) {
                hash = ((hash << 5) + hash) + (unsigned char)*p++;
            }
            selected = healthy_indices[hash % healthy_count];
        } else {
            selected = healthy_indices[0];
        }
        break;

    default:
        selected = healthy_indices[0];
        break;
    }

    return selected;
}

int router_resolve(router_t *router, const char *username,
                   const char *target, route_result_t *result)
{
    if (router == NULL || result == NULL) {
        return -1;
    }

    memset(result, 0, sizeof(*result));

    /* Try to match rules first */
    route_rule_t *rule = router->rules;
    while (rule != NULL) {
        if (!rule->enabled) {
            rule = rule->next;
            continue;
        }

        bool username_match = (rule->match_username[0] == '\0' ||
                               router_glob_match(rule->match_username, username ? username : ""));
        bool target_match = (rule->match_target[0] == '\0' ||
                             router_glob_match(rule->match_target, target ? target : ""));

        if (username_match && target_match) {
            int idx = rule->upstream_index;
            if (idx < 0) {
                idx = router->default_upstream;
            }
            if (idx >= 0 && (size_t)idx < router->upstream_count) {
                result->upstream = &router->upstreams[idx];
                result->upstream_index = idx;
                result->matched_rule = rule->name;
                LOG_DEBUG("Route matched rule '%s' -> upstream %d", rule->name, idx);
                return 0;
            }
        }
        rule = rule->next;
    }

    /* No rule matched, use load balancing */
    int selected = select_upstream_lb(router, username);
    if (selected >= 0) {
        result->upstream = &router->upstreams[selected];
        result->upstream_index = selected;
        result->matched_rule = NULL;
        LOG_DEBUG("Route using LB -> upstream %d", selected);
        return 0;
    }

    LOG_WARN("No route found for user='%s', target='%s'",
             username ? username : "(null)", target ? target : "(null)");
    return -1;
}

ssh_session router_connect(router_t *router, route_result_t *result,
                           uint32_t timeout_ms)
{
    if (router == NULL || result == NULL || result->upstream == NULL) {
        return NULL;
    }

    upstream_t *upstream = result->upstream;

    /* Create SSH session */
    ssh_session session = ssh_new();
    if (session == NULL) {
        LOG_ERROR("Failed to create SSH session");
        return NULL;
    }

    /* Set connection options */
    ssh_options_set(session, SSH_OPTIONS_HOST, upstream->config.host);
    ssh_options_set(session, SSH_OPTIONS_PORT, &upstream->config.port);

    long timeout_sec = timeout_ms / 1000;
    if (timeout_sec == 0) {
        timeout_sec = 10;
    }
    ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout_sec);

    /* Set strict host key checking to "no" for now */
    ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &(int){0});

    LOG_DEBUG("Connecting to upstream %s:%d",
              upstream->config.host, upstream->config.port);

    /* Connect */
    int rc = ssh_connect(session);
    if (rc != SSH_OK) {
        LOG_ERROR("Failed to connect to upstream %s:%d: %s",
                  upstream->config.host, upstream->config.port,
                  ssh_get_error(session));
        ssh_free(session);
        router_notify_connect(router, result->upstream_index, false);
        return NULL;
    }

    router_notify_connect(router, result->upstream_index, true);
    LOG_INFO("Connected to upstream %s:%d",
             upstream->config.host, upstream->config.port);

    return session;
}

void router_notify_connect(router_t *router, int upstream_index, bool success)
{
    if (router == NULL || upstream_index < 0 ||
        (size_t)upstream_index >= router->upstream_count) {
        return;
    }

    upstream_t *upstream = &router->upstreams[upstream_index];

    if (success) {
        upstream->active_connections++;
        upstream->total_connections++;
        upstream->consecutive_failures = 0;
        upstream->health = UPSTREAM_HEALTH_HEALTHY;
    } else {
        upstream->consecutive_failures++;
        upstream->last_failure = time(NULL);

        /* Mark unhealthy after 3 consecutive failures */
        if (upstream->consecutive_failures >= 3) {
            upstream->health = UPSTREAM_HEALTH_UNHEALTHY;
            LOG_WARN("Upstream %d marked unhealthy after %d failures",
                     upstream_index, upstream->consecutive_failures);
        }
    }
}

void router_notify_close(router_t *router, int upstream_index)
{
    if (router == NULL || upstream_index < 0 ||
        (size_t)upstream_index >= router->upstream_count) {
        return;
    }

    upstream_t *upstream = &router->upstreams[upstream_index];
    if (upstream->active_connections > 0) {
        upstream->active_connections--;
    }
}

void router_health_check(router_t *router)
{
    if (router == NULL || !router->config.health_check_enabled) {
        return;
    }

    time_t now = time(NULL);

    for (size_t i = 0; i < router->upstream_count; i++) {
        upstream_t *upstream = &router->upstreams[i];

        if (!upstream->config.enabled) {
            continue;
        }

        /* Check if health check is due */
        if ((now - upstream->last_check) < (time_t)router->config.health_check_interval) {
            continue;
        }

        upstream->last_check = now;

        /* Simple TCP connect check */
        ssh_session session = ssh_new();
        if (session == NULL) {
            continue;
        }

        ssh_options_set(session, SSH_OPTIONS_HOST, upstream->config.host);
        ssh_options_set(session, SSH_OPTIONS_PORT, &upstream->config.port);
        ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &(long){5});

        int rc = ssh_connect(session);
        if (rc == SSH_OK) {
            if (upstream->health == UPSTREAM_HEALTH_UNHEALTHY) {
                LOG_INFO("Upstream %zu is now healthy", i);
            }
            upstream->health = UPSTREAM_HEALTH_HEALTHY;
            upstream->consecutive_failures = 0;
            ssh_disconnect(session);
        } else {
            if (upstream->health != UPSTREAM_HEALTH_UNHEALTHY) {
                LOG_WARN("Upstream %zu health check failed", i);
            }
            upstream->health = UPSTREAM_HEALTH_UNHEALTHY;
        }

        ssh_free(session);
    }
}

int router_set_default_upstream(router_t *router, int index)
{
    if (router == NULL) {
        return -1;
    }

    if (index < 0 || (size_t)index >= router->upstream_count) {
        return -1;
    }

    router->default_upstream = index;
    LOG_DEBUG("Default upstream set to %d", index);
    return 0;
}
