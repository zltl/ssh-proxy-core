/**
 * @file proxy_handler.c
 * @brief SSH Proxy Core - Connection Handler Implementation
 */

#define _DEFAULT_SOURCE
#include "proxy_handler.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

/* Suppress deprecated warnings for ssh_message functions */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#define BUF_SIZE 16384

/* Helper to clean up context */
static void free_context(proxy_handler_context_t *ctx) {
    if (ctx) {
        /* Session is managed by session_manager, but we need to remove it */
        if (ctx->session_mgr && ctx->session) {
            session_manager_remove_session(ctx->session_mgr, ctx->session);
        }
        free(ctx);
    }
}

/* Setup authentication callbacks and perform handshake */
static int setup_auth_and_handshake(proxy_handler_context_t *ctx, char **username_out) {
    ssh_session session = session_get_client(ctx->session);
    
    session_set_state(ctx->session, SESSION_STATE_AUTH);
    
    /* Perform key exchange first */
    if (ssh_handle_key_exchange(session) != SSH_OK) {
        LOG_ERROR("Key exchange failed: %s", ssh_get_error(session));
        return -1;
    }
    
    /* Handle authentication messages manually */
    ssh_message message;
    int auth_attempts = 0;
    const int max_attempts = 3;
    bool authenticated = false;
    
    while (!authenticated && auth_attempts < max_attempts) {
        message = ssh_message_get(session);
        if (!message) {
            continue; /* Wait for client to send auth request */
        }
        
        /* Handle authentication messages */
        if (ssh_message_type(message) == SSH_REQUEST_AUTH) {
            const char *user = ssh_message_auth_user(message);
            if (user && *username_out == NULL) {
                *username_out = strdup(user);
                session_set_username(ctx->session, user);
            }
            
            int subtype = ssh_message_subtype(message);
            filter_context_t filter_ctx = {
                .session = ctx->session,
                .username = user,
                .password = NULL,
                .pubkey = NULL,
                .pubkey_len = 0
            };
            
            if (subtype == SSH_AUTH_METHOD_PASSWORD) {
                filter_ctx.password = ssh_message_auth_password(message);
                LOG_DEBUG("Password auth attempt for user '%s'", user);
                
                /* Run auth filters only for password/pubkey auth */
                filter_status_t status = filter_chain_on_auth(ctx->filters, &filter_ctx);
                
                if (status == FILTER_CONTINUE) {
                    authenticated = true;
                    ssh_message_auth_reply_success(message, 0);
                    LOG_INFO("User '%s' authenticated successfully", user);
                } else {
                    auth_attempts++;
                    ssh_message_reply_default(message);
                    LOG_WARN("Authentication failed for user '%s' (attempt %d/%d)", 
                             user, auth_attempts, max_attempts);
                }
            } else if (subtype == SSH_AUTH_METHOD_PUBLICKEY) {
                /* For now, just set a placeholder */
                filter_ctx.pubkey = (void*)"pubkey";
                filter_ctx.pubkey_len = 6;
                LOG_DEBUG("Public key auth attempt for user '%s'", user);
                
                /* Run auth filters only for password/pubkey auth */
                filter_status_t status = filter_chain_on_auth(ctx->filters, &filter_ctx);
                
                if (status == FILTER_CONTINUE) {
                    authenticated = true;
                    ssh_message_auth_reply_success(message, 0);
                    LOG_INFO("User '%s' authenticated successfully with public key", user);
                } else {
                    auth_attempts++;
                    ssh_message_reply_default(message);
                    LOG_WARN("Public key authentication failed for user '%s' (attempt %d/%d)", 
                             user, auth_attempts, max_attempts);
                }
            } else {
                /* Handle other auth methods (like "none") - just reject them */
                LOG_DEBUG("Unsupported auth method %d for user '%s'", subtype, user);
                ssh_message_reply_default(message);
            }
        } else {
            ssh_message_reply_default(message);
        }
        
        ssh_message_free(message);
    }
    
    return authenticated ? 0 : -1;
}

/* Connect to upstream */
static ssh_session connect_upstream(proxy_handler_context_t *ctx, const char *username) {
    route_result_t route;
    /* TODO: Get target from somewhere? For now assume default or based on username */
    const char *target = "default"; 

    if (router_resolve(ctx->router, username, target, &route) != 0) {
        LOG_ERROR("No route found for user '%s'", username);
        return NULL;
    }

    /* Update session metadata */
    session_metadata_t *meta = session_get_metadata(ctx->session);
    if (meta) {
        strncpy(meta->target_addr, route.upstream->config.host, sizeof(meta->target_addr) - 1);
        meta->target_port = route.upstream->config.port;
    }

    /* Connect */
    ssh_session upstream = router_connect(ctx->router, &route, 10000);
    if (upstream == NULL) {
        return NULL;
    }

    /* Authenticate to upstream */
    /* TODO: Implement proper upstream auth. For now, try "none" or fail. 
       In a real proxy, we might forward the user's creds or use a system key. */
    int rc = ssh_userauth_none(upstream, NULL);
    if (rc != SSH_AUTH_SUCCESS) {
        /* Try public key auto-login if available */
        rc = ssh_userauth_publickey_auto(upstream, NULL, NULL);
        if (rc != SSH_AUTH_SUCCESS) {
             LOG_ERROR("Failed to authenticate to upstream %s", route.upstream->config.host);
             ssh_disconnect(upstream);
             ssh_free(upstream);
             return NULL;
        }
    }

    return upstream;
}

/* Forwarding loop */
static void forward_loop(ssh_session client, ssh_session upstream, ssh_channel client_chan, ssh_channel upstream_channel) {
    (void)client;
    (void)upstream;
    char buf[BUF_SIZE];
    int nbytes, rc;

    /* Simple select loop */
    while (ssh_channel_is_open(client_chan) && ssh_channel_is_open(upstream_channel)) {
        /* Wait for data on either channel */
        /* Note: libssh select is a bit tricky, using polling for simplicity in this iteration */
        /* In production, use ssh_event loop */
        
        /* Read from client, write to upstream */
        nbytes = ssh_channel_read_nonblocking(client_chan, buf, sizeof(buf), 0);
        if (nbytes > 0) {
            rc = ssh_channel_write(upstream_channel, buf, nbytes);
            if (rc < 0) break;
        } else if (nbytes < 0) {
            break; /* Error */
        }

        /* Read from upstream, write to client */
        nbytes = ssh_channel_read_nonblocking(upstream_channel, buf, sizeof(buf), 0);
        if (nbytes > 0) {
            rc = ssh_channel_write(client_chan, buf, nbytes);
            if (rc < 0) break;
        } else if (nbytes < 0) {
            break; /* Error */
        }

        /* Check for EOF */
        if (ssh_channel_is_eof(client_chan) || ssh_channel_is_eof(upstream_channel)) {
            break;
        }

        usleep(1000); /* 1ms sleep to prevent CPU spin */
    }
}

void *proxy_handler_run(void *arg) {
    proxy_handler_context_t *ctx = (proxy_handler_context_t *)arg;
    ssh_session client_session = session_get_client(ctx->session);
    char *username = NULL;
    ssh_session upstream_session = NULL;
    ssh_channel client_channel = NULL;
    ssh_channel upstream_channel = NULL;

    LOG_INFO("Handler started for session %lu", session_get_id(ctx->session));

    /* 1. Setup auth callbacks and perform handshake/auth */
    if (setup_auth_and_handshake(ctx, &username) != 0) {
        goto cleanup;
    }
    session_set_state(ctx->session, SESSION_STATE_AUTHENTICATED);

    /* 2. Connect to Upstream */
    upstream_session = connect_upstream(ctx, username);
    if (upstream_session == NULL) {
        LOG_ERROR("Failed to connect to upstream");
        goto cleanup;
    }
    session_set_upstream(ctx->session, upstream_session);

    /* 3. Open Channel */
    /* Wait for channel open request from client */
    ssh_message message;
    while ((message = ssh_message_get(client_session))) {
        if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
            ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
            
            client_channel = ssh_message_channel_request_open_reply_accept(message);
            ssh_message_free(message);
            break;
        }
        ssh_message_reply_default(message);
        ssh_message_free(message);
    }

    if (client_channel == NULL) {
        LOG_ERROR("Client did not request session channel");
        goto cleanup;
    }

    /* Open channel to upstream */
    upstream_channel = ssh_channel_new(upstream_session);
    if (ssh_channel_open_session(upstream_channel) != SSH_OK) {
        LOG_ERROR("Failed to open upstream channel");
        goto cleanup;
    }

    /* 4. Handle Shell/Exec/Subsystem requests */
    /* For simplicity, we just accept the first request (likely shell or exec) and start forwarding */
    /* In a real proxy, we need to forward the request type to upstream */
    
    while ((message = ssh_message_get(client_session))) {
        if (ssh_message_type(message) == SSH_REQUEST_CHANNEL &&
            ssh_message_channel_request_channel(message) == client_channel) {
            
            int subtype = ssh_message_subtype(message);
            if (subtype == SSH_CHANNEL_REQUEST_SHELL) {
                ssh_channel_request_shell(upstream_channel);
                ssh_message_channel_request_reply_success(message);
                ssh_message_free(message);
                break;
            } else if (subtype == SSH_CHANNEL_REQUEST_PTY) {
                ssh_channel_request_pty(upstream_channel);
                ssh_channel_change_pty_size(upstream_channel,
                    ssh_message_channel_request_pty_width(message),
                    ssh_message_channel_request_pty_height(message));
                
                ssh_message_channel_request_reply_success(message);
                ssh_message_free(message);
                /* Continue loop to wait for shell/exec */
                continue; 
            } else if (subtype == SSH_CHANNEL_REQUEST_EXEC) {
                ssh_channel_request_exec(upstream_channel, ssh_message_channel_request_command(message));
                ssh_message_channel_request_reply_success(message);
                ssh_message_free(message);
                break;
            }
        }
        ssh_message_reply_default(message);
        ssh_message_free(message);
    }

    session_set_state(ctx->session, SESSION_STATE_ACTIVE);
    LOG_INFO("Session %lu active, forwarding...", session_get_id(ctx->session));

    /* 5. Forward Data */
    forward_loop(client_session, upstream_session, client_channel, upstream_channel);

cleanup:
    LOG_INFO("Session %lu ending", session_get_id(ctx->session));
    
    if (client_channel) {
        ssh_channel_send_eof(client_channel);
        ssh_channel_close(client_channel);
        ssh_channel_free(client_channel);
    }
    if (upstream_channel) {
        ssh_channel_close(upstream_channel);
        ssh_channel_free(upstream_channel);
    }
    if (upstream_session) {
        ssh_disconnect(upstream_session);
        /* ssh_free(upstream_session); - Managed by session_manager */
    }
    
    /* Client session is freed by session_manager_remove_session in free_context */
    /* But we should disconnect it */
    ssh_disconnect(client_session);
    
    if (username) free(username);
    free_context(ctx);
    return NULL;
}
