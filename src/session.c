/**
 * @file session.c
 * @brief SSH Proxy Core - Session Manager Implementation
 */

#include "session.h"
#include "logger.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* Session structure */
struct session {
    uint64_t id;                    /* Unique session ID */
    session_state_t state;          /* Current state */
    ssh_session client;             /* Client SSH session */
    ssh_session upstream;           /* Upstream SSH session */
    session_metadata_t metadata;    /* Session metadata */
    session_stats_t stats;          /* Session statistics */
    session_t *next;                /* Linked list next pointer */
    session_t *prev;                /* Linked list prev pointer */
};

/* Session manager structure */
struct session_manager {
    session_manager_config_t config;
    session_t *sessions;            /* Linked list of sessions */
    size_t session_count;           /* Current session count */
    uint64_t next_id;               /* Next session ID */
    pthread_mutex_t lock;           /* Thread safety lock */
};

/* State names */
static const char *state_names[] = {
    "NEW",
    "HANDSHAKE",
    "AUTH",
    "AUTHENTICATED",
    "ROUTING",
    "CONNECTING",
    "ACTIVE",
    "CLOSING",
    "CLOSED"
};

session_manager_t *session_manager_create(const session_manager_config_t *config)
{
    if (config == NULL) {
        return NULL;
    }

    session_manager_t *manager = calloc(1, sizeof(session_manager_t));
    if (manager == NULL) {
        return NULL;
    }

    manager->config = *config;
    manager->sessions = NULL;
    manager->session_count = 0;
    manager->next_id = 1;

    if (pthread_mutex_init(&manager->lock, NULL) != 0) {
        free(manager);
        return NULL;
    }

    LOG_DEBUG("Session manager created, max_sessions=%zu", config->max_sessions);
    return manager;
}

void session_manager_destroy(session_manager_t *manager)
{
    if (manager == NULL) {
        return;
    }

    pthread_mutex_lock(&manager->lock);

    /* Destroy all sessions */
    session_t *session = manager->sessions;
    while (session != NULL) {
        session_t *next = session->next;

        if (session->upstream != NULL) {
            ssh_disconnect(session->upstream);
            ssh_free(session->upstream);
        }
        if (session->client != NULL) {
            ssh_disconnect(session->client);
            ssh_free(session->client);
        }
        free(session);

        session = next;
    }

    pthread_mutex_unlock(&manager->lock);
    pthread_mutex_destroy(&manager->lock);

    free(manager);
    LOG_DEBUG("Session manager destroyed");
}

session_t *session_manager_create_session(session_manager_t *manager,
                                          ssh_session client_session)
{
    if (manager == NULL || client_session == NULL) {
        return NULL;
    }

    pthread_mutex_lock(&manager->lock);

    /* Check session limit */
    if (manager->session_count >= manager->config.max_sessions) {
        LOG_WARN("Maximum session limit reached (%zu)", manager->config.max_sessions);
        pthread_mutex_unlock(&manager->lock);
        return NULL;
    }

    /* Create new session */
    session_t *session = calloc(1, sizeof(session_t));
    if (session == NULL) {
        pthread_mutex_unlock(&manager->lock);
        return NULL;
    }

    session->id = manager->next_id++;
    session->state = SESSION_STATE_NEW;
    session->client = client_session;
    session->upstream = NULL;
    session->stats.start_time = time(NULL);
    session->stats.last_activity = session->stats.start_time;

    /* Add to linked list */
    session->next = manager->sessions;
    session->prev = NULL;
    if (manager->sessions != NULL) {
        manager->sessions->prev = session;
    }
    manager->sessions = session;
    manager->session_count++;

    LOG_DEBUG("Session %lu created, total=%zu", session->id, manager->session_count);

    pthread_mutex_unlock(&manager->lock);
    return session;
}

void session_manager_remove_session(session_manager_t *manager,
                                    session_t *session)
{
    if (manager == NULL || session == NULL) {
        return;
    }

    pthread_mutex_lock(&manager->lock);

    /* Remove from linked list */
    if (session->prev != NULL) {
        session->prev->next = session->next;
    } else {
        manager->sessions = session->next;
    }
    if (session->next != NULL) {
        session->next->prev = session->prev;
    }

    manager->session_count--;
    uint64_t session_id = session->id;

    /* Cleanup session resources */
    if (session->upstream != NULL) {
        ssh_disconnect(session->upstream);
        ssh_free(session->upstream);
    }
    if (session->client != NULL) {
        ssh_disconnect(session->client);
        ssh_free(session->client);
    }

    free(session);

    LOG_DEBUG("Session %lu removed, remaining=%zu", session_id, manager->session_count);

    pthread_mutex_unlock(&manager->lock);
}

size_t session_manager_get_count(const session_manager_t *manager)
{
    if (manager == NULL) {
        return 0;
    }
    return manager->session_count;
}

session_t *session_manager_find(session_manager_t *manager, uint64_t session_id)
{
    if (manager == NULL) {
        return NULL;
    }

    pthread_mutex_lock(&manager->lock);

    session_t *session = manager->sessions;
    while (session != NULL) {
        if (session->id == session_id) {
            pthread_mutex_unlock(&manager->lock);
            return session;
        }
        session = session->next;
    }

    pthread_mutex_unlock(&manager->lock);
    return NULL;
}

size_t session_manager_cleanup(session_manager_t *manager)
{
    if (manager == NULL) {
        return 0;
    }

    pthread_mutex_lock(&manager->lock);

    size_t cleaned = 0;
    time_t now = time(NULL);
    session_t *session = manager->sessions;

    while (session != NULL) {
        session_t *next = session->next;

        uint32_t timeout = manager->config.session_timeout;
        if (session->state < SESSION_STATE_AUTHENTICATED) {
            timeout = manager->config.auth_timeout;
        }

        if ((now - session->stats.last_activity) > timeout) {
            LOG_INFO("Session %lu timed out (idle %ld seconds)",
                     session->id, now - session->stats.last_activity);

            /* Remove from list */
            if (session->prev != NULL) {
                session->prev->next = session->next;
            } else {
                manager->sessions = session->next;
            }
            if (session->next != NULL) {
                session->next->prev = session->prev;
            }

            manager->session_count--;

            /* Cleanup */
            if (session->upstream != NULL) {
                ssh_disconnect(session->upstream);
                ssh_free(session->upstream);
            }
            if (session->client != NULL) {
                ssh_disconnect(session->client);
                ssh_free(session->client);
            }
            free(session);
            cleaned++;
        }

        session = next;
    }

    pthread_mutex_unlock(&manager->lock);

    if (cleaned > 0) {
        LOG_DEBUG("Cleaned up %zu timed-out sessions", cleaned);
    }

    return cleaned;
}

/* Session operations */

uint64_t session_get_id(const session_t *session)
{
    if (session == NULL) {
        return 0;
    }
    return session->id;
}

session_state_t session_get_state(const session_t *session)
{
    if (session == NULL) {
        return SESSION_STATE_CLOSED;
    }
    return session->state;
}

void session_set_state(session_t *session, session_state_t state)
{
    if (session == NULL) {
        return;
    }

    LOG_DEBUG("Session %lu: %s -> %s",
              session->id,
              session_state_name(session->state),
              session_state_name(state));

    session->state = state;
}

ssh_session session_get_client(session_t *session)
{
    if (session == NULL) {
        return NULL;
    }
    return session->client;
}

ssh_session session_get_upstream(session_t *session)
{
    if (session == NULL) {
        return NULL;
    }
    return session->upstream;
}

void session_set_upstream(session_t *session, ssh_session upstream)
{
    if (session == NULL) {
        return;
    }
    session->upstream = upstream;
}

void session_set_username(session_t *session, const char *username)
{
    if (session == NULL || username == NULL) {
        return;
    }
    strncpy(session->metadata.username, username, SESSION_MAX_USERNAME - 1);
    session->metadata.username[SESSION_MAX_USERNAME - 1] = '\0';
}

session_metadata_t *session_get_metadata(session_t *session)
{
    if (session == NULL) {
        return NULL;
    }
    return &session->metadata;
}

session_stats_t *session_get_stats(session_t *session)
{
    if (session == NULL) {
        return NULL;
    }
    return &session->stats;
}

void session_touch(session_t *session)
{
    if (session == NULL) {
        return;
    }
    session->stats.last_activity = time(NULL);
}

bool session_is_timeout(const session_t *session, uint32_t timeout_seconds)
{
    if (session == NULL) {
        return true;
    }
    time_t now = time(NULL);
    return (now - session->stats.last_activity) > timeout_seconds;
}

const char *session_state_name(session_state_t state)
{
    if (state >= 0 && state <= SESSION_STATE_CLOSED) {
        return state_names[state];
    }
    return "UNKNOWN";
}
