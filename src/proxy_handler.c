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
    const char *upstream_host = "127.0.0.1";
    uint16_t upstream_port = 22;
    const char *upstream_user = NULL;
    const char *privkey_path = NULL;
    
    /* First, try to find route from config */
    if (ctx->config != NULL) {
        config_route_t *route = config_find_route(ctx->config, username);
        if (route != NULL) {
            upstream_host = route->upstream_host;
            upstream_port = route->upstream_port;
            upstream_user = route->upstream_user[0] ? route->upstream_user : NULL;
            privkey_path = route->privkey_path[0] ? route->privkey_path : NULL;
            LOG_INFO("Route found for user '%s' -> %s:%u (user=%s)", 
                     username, upstream_host, upstream_port, 
                     upstream_user ? upstream_user : "(default)");
        } else {
            LOG_WARN("No route found for user '%s', using default", username);
        }
    }
    
    /* Update session metadata */
    session_metadata_t *meta = session_get_metadata(ctx->session);
    if (meta) {
        strncpy(meta->target_addr, upstream_host, sizeof(meta->target_addr) - 1);
        meta->target_port = upstream_port;
    }

    /* Connect to upstream SSH server */
    ssh_session upstream = ssh_new();
    if (upstream == NULL) {
        LOG_ERROR("Failed to create upstream SSH session");
        return NULL;
    }
    
    ssh_options_set(upstream, SSH_OPTIONS_HOST, upstream_host);
    ssh_options_set(upstream, SSH_OPTIONS_PORT, &upstream_port);
    if (upstream_user != NULL) {
        ssh_options_set(upstream, SSH_OPTIONS_USER, upstream_user);
    }
    
    LOG_DEBUG("Connecting to upstream %s:%u", upstream_host, upstream_port);
    
    if (ssh_connect(upstream) != SSH_OK) {
        LOG_ERROR("Failed to connect to upstream %s:%u: %s", 
                  upstream_host, upstream_port, ssh_get_error(upstream));
        ssh_free(upstream);
        return NULL;
    }
    
    LOG_INFO("Connected to upstream %s:%u", upstream_host, upstream_port);

    /* Authenticate to upstream */
    int rc = SSH_AUTH_DENIED;
    
    /* Try private key if specified */
    if (privkey_path != NULL) {
        LOG_DEBUG("Trying private key auth with %s", privkey_path);
        ssh_key privkey = NULL;
        if (ssh_pki_import_privkey_file(privkey_path, NULL, NULL, NULL, &privkey) == SSH_OK) {
            rc = ssh_userauth_publickey(upstream, upstream_user, privkey);
            ssh_key_free(privkey);
            if (rc == SSH_AUTH_SUCCESS) {
                LOG_INFO("Upstream auth successful with private key");
                return upstream;
            }
        } else {
            LOG_WARN("Failed to load private key: %s", privkey_path);
        }
    }
    
    /* Try publickey auto (uses SSH agent or default keys) */
    if (rc != SSH_AUTH_SUCCESS) {
        rc = ssh_userauth_publickey_auto(upstream, upstream_user, NULL);
        if (rc == SSH_AUTH_SUCCESS) {
            LOG_INFO("Upstream auth successful with auto publickey");
            return upstream;
        }
    }
    
    /* Try none auth */
    if (rc != SSH_AUTH_SUCCESS) {
        rc = ssh_userauth_none(upstream, upstream_user);
        if (rc == SSH_AUTH_SUCCESS) {
            LOG_INFO("Upstream auth successful with none");
            return upstream;
        }
    }
    
    LOG_ERROR("Failed to authenticate to upstream %s:%u", upstream_host, upstream_port);
    ssh_disconnect(upstream);
    ssh_free(upstream);
    return NULL;
}

/* Forwarding loop with audit recording */
static void forward_loop(proxy_handler_context_t *ctx, 
                         ssh_channel client_chan, 
                         ssh_channel upstream_channel,
                         const char *username) {
    char buf[BUF_SIZE];
    int nbytes, rc;
    
    /* Create filter context for data callbacks */
    filter_context_t filter_ctx = {
        .session = ctx->session,
        .username = username,
        .user_data = NULL
    };

    /* Simple select loop */
    while (ssh_channel_is_open(client_chan) && ssh_channel_is_open(upstream_channel)) {
        /* Read from client, write to upstream */
        nbytes = ssh_channel_read_nonblocking(client_chan, buf, sizeof(buf), 0);
        if (nbytes > 0) {
            /* Call filter chain for upstream data (client -> upstream) */
            if (ctx->filters != NULL) {
                filter_chain_on_data_upstream(ctx->filters, &filter_ctx, 
                                              (const uint8_t *)buf, (size_t)nbytes);
            }
            
            rc = ssh_channel_write(upstream_channel, buf, nbytes);
            if (rc < 0) break;
        } else if (nbytes < 0) {
            break; /* Error */
        }

        /* Read from upstream, write to client */
        nbytes = ssh_channel_read_nonblocking(upstream_channel, buf, sizeof(buf), 0);
        if (nbytes > 0) {
            /* Call filter chain for downstream data (upstream -> client) */
            if (ctx->filters != NULL) {
                filter_chain_on_data_downstream(ctx->filters, &filter_ctx,
                                                (const uint8_t *)buf, (size_t)nbytes);
            }
            
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
    
    /* Notify filters of successful authentication */
    if (ctx->filters != NULL) {
        filter_context_t auth_ctx = {
            .session = ctx->session,
            .username = username,
            .user_data = NULL
        };
        filter_chain_on_authenticated(ctx->filters, &auth_ctx);
    }

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
                /* Get terminal type and dimensions from client request */
                const char *term = ssh_message_channel_request_pty_term(message);
                int width = ssh_message_channel_request_pty_width(message);
                int height = ssh_message_channel_request_pty_height(message);
                
                LOG_DEBUG("PTY request: term=%s, size=%dx%d", 
                          term ? term : "unknown", width, height);
                
                /* Request PTY on upstream with same terminal type */
                ssh_channel_request_pty_size(upstream_channel, 
                                             term ? term : "xterm-256color",
                                             width, height);
                
                ssh_message_channel_request_reply_success(message);
                ssh_message_free(message);
                /* Continue loop to wait for shell/exec */
                continue; 
            } else if (subtype == SSH_CHANNEL_REQUEST_EXEC) {
                ssh_channel_request_exec(upstream_channel, ssh_message_channel_request_command(message));
                ssh_message_channel_request_reply_success(message);
                ssh_message_free(message);
                break;
            } else if (subtype == SSH_CHANNEL_REQUEST_ENV) {
                /* Forward environment variables */
                const char *env_name = ssh_message_channel_request_env_name(message);
                const char *env_value = ssh_message_channel_request_env_value(message);
                if (env_name && env_value) {
                    ssh_channel_request_env(upstream_channel, env_name, env_value);
                }
                ssh_message_channel_request_reply_success(message);
                ssh_message_free(message);
                continue;
            } else if (subtype == SSH_CHANNEL_REQUEST_WINDOW_CHANGE) {
                /* Forward window size changes */
                int new_width = ssh_message_channel_request_pty_width(message);
                int new_height = ssh_message_channel_request_pty_height(message);
                ssh_channel_change_pty_size(upstream_channel, new_width, new_height);
                ssh_message_channel_request_reply_success(message);
                ssh_message_free(message);
                continue;
            }
        }
        ssh_message_reply_default(message);
        ssh_message_free(message);
    }

    session_set_state(ctx->session, SESSION_STATE_ACTIVE);
    LOG_INFO("Session %lu active, forwarding...", session_get_id(ctx->session));

    /* 5. Forward Data with audit recording */
    forward_loop(ctx, client_channel, upstream_channel, username);

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
    
    /* Notify filters of session close */
    if (ctx->filters != NULL) {
        filter_context_t close_ctx = {
            .session = ctx->session,
            .username = username,
            .user_data = NULL
        };
        filter_chain_on_close(ctx->filters, &close_ctx);
    }
    
    /* Client session is freed by session_manager_remove_session in free_context */
    /* But we should disconnect it */
    ssh_disconnect(client_session);
    
    if (username) free(username);
    free_context(ctx);
    return NULL;
}
