#include "osdep_service.h"
#include "platform_stdlib.h"

#include "lwip/sockets.h"

#include <websocket/wsserver_api.h>
#include <websocket/ws_server_msg.h>
//#include <wlan_basic_types.h>
struct task_struct	ws_server_conn_tsk;
struct task_struct	ws_server_tsk;
// setting
#define WS_SERVER_DEFAULT_PORT				80
#define WS_SERVER_DEFAULT_SECURE_PORT		443
#define WS_SERVER_DEFAULT_MAX_CONN			1
#define WS_SERVER_DEFAULT_STACK_BYTES		4096
#define WS_SERVER_PRIORITY					(tskIDLE_PRIORITY + 1)
#define WS_SERVER_DEFAULT_SELECT_TIMEOUT	50
#define WS_SERVER_LISTEN_LEN				3
#define WS_SERVER_RECV_TIMEOUT				5
#define WS_SERVER_MAGIC_STRING				"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_SERVER_DEFAULT_TX_SIZE			256
#define WS_SERVER_DEFAULT_RX_SIZE			256
#define WS_SERVER_DEFAULT_PING_INTERVAL		30000

static uint16_t ws_server_port = WS_SERVER_DEFAULT_PORT;
static uint32_t ws_server_stack_bytes = WS_SERVER_DEFAULT_STACK_BYTES;
uint8_t ws_server_max_conn = WS_SERVER_DEFAULT_MAX_CONN;
static uint8_t ws_server_secure = WS_SERVER_SECURE_NONE;
static int ws_server_select_timeout = WS_SERVER_DEFAULT_SELECT_TIMEOUT;
static int ws_server_ping_interval = WS_SERVER_DEFAULT_PING_INTERVAL;
static int ws_server_idle_timeout = 0;
uint8_t ws_server_debug = WS_SERVER_DEBUG_ON;
size_t ws_server_tx_size = WS_SERVER_DEFAULT_TX_SIZE;
size_t ws_server_rx_size = WS_SERVER_DEFAULT_RX_SIZE;

// run-time
static uint8_t ws_server_running = 0;
static int ws_server_sock = -1;
static int ws_server_max_sock = -1;
ws_conn *ws_server_connections = NULL;
size_t ws_server_tmp_buf_size = 1024;

static void ws_server_setup(uint16_t port, uint8_t max_conn, uint8_t secure)
{
	ws_server_log_verbose("%s port:%d, max_conn:%d, secure:%d", __FUNCTION__, port, max_conn, secure);

	if (port > 0) {
		ws_server_port = port;
	} else if (secure) {
		ws_server_port = WS_SERVER_DEFAULT_SECURE_PORT;
	}

	if (max_conn > 0) {
		ws_server_max_conn = max_conn;
	}

	ws_server_secure = secure;
}

static int ws_server_init(void)
{
	int ret = 0;
	ws_server_log_verbose("%s start", __FUNCTION__);

	ws_server_connections = (ws_conn *)ws_server_malloc(sizeof(ws_conn) * ws_server_max_conn);
	if (ws_server_connections) {
		int i;
		memset(ws_server_connections, 0, (sizeof(ws_conn) * ws_server_max_conn));
		for (i = 0; i < ws_server_max_conn; i ++) {
			ws_server_connections[i].sock = -1;
		}
	} else {
		ret = -1;
		goto exit;
	}

	if ((ws_server_sock = socket(AF_INET, SOCK_STREAM, 0)) >= 0) {
		struct sockaddr_in ws_server_addr;
		int enable = 1;

		ws_server_addr.sin_family = AF_INET;
		ws_server_addr.sin_port = htons(ws_server_port);
		ws_server_addr.sin_addr.s_addr = INADDR_ANY;

		if (setsockopt(ws_server_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&enable, sizeof(enable)) != 0) {
			ws_server_log("ERROR: SO_REUSEADDR\n");
		}

		if ((ret = bind(ws_server_sock, (struct sockaddr *) &ws_server_addr, sizeof(ws_server_addr))) != 0) {
			ws_server_log("ERROR: bind");
			goto exit;
		}

		if ((ret = listen(ws_server_sock, WS_SERVER_LISTEN_LEN)) != 0) {
			ws_server_log("ERROR: listen");
			goto exit;
		}

		ws_server_max_sock = ws_server_sock;
	} else {
		ret = -1;
		goto exit;
	}
	ws_server_log("Websocket server start\n");
exit:
	if (ret) {
		if (ws_server_sock != -1) {
			close(ws_server_sock);
			ws_server_sock = -1;
		}

		if (ws_server_connections) {
			ws_server_free(ws_server_connections);
			ws_server_connections = NULL;
		}
	}

	return ret;
}

static void ws_server_deinit(void)
{
	// free ws_server resource
	ws_server_free(ws_server_connections);
	ws_server_connections = NULL;

	if (ws_server_sock != -1) {
		close(ws_server_sock);
		ws_server_sock = -1;
	}

	if (ws_server_secure) {
		ws_server_tls_setup_free();
	}
}

static int ws_server_conn_init(ws_conn *conn)
{
	ws_server_log_verbose("%s to state CONNECTING, TX LENGTH:%d, RX LENGTH:%d", __FUNCTION__, ws_server_tx_size, ws_server_rx_size);
	conn->txbuf = (uint8_t *)ws_server_malloc(ws_server_tx_size + 16);
	conn->rxbuf = (uint8_t *)ws_server_malloc(ws_server_rx_size + 16);
	conn->receivedData = (uint8_t *)ws_server_malloc(ws_server_rx_size);
	if (!conn->txbuf || !conn->rxbuf || !conn->receivedData) {
		ws_server_log("ERROR: Malloc tx rx buffer memory fail\n");
		return -1;
	}
	memset(conn->txbuf, 0, ws_server_tx_size + 16);
	memset(conn->rxbuf, 0, ws_server_rx_size + 16);
	memset(conn->receivedData, 0, ws_server_rx_size);
	return 0;
}

void ws_server_conn_remove(ws_conn *conn)
{
	int i;

	for (i = 0; i < ws_server_max_conn; i ++) {
		if (&ws_server_connections[i] == conn) {
			ws_server_log_verbose("%s remove connection %d", __FUNCTION__, conn->sock);
			if (ws_server_connections[i].tls) {
				ws_server_tls_close(ws_server_connections[i].tls);
				ws_server_tls_free(ws_server_connections[i].tls);
			}

			if (ws_server_connections[i].sock != -1) {
				close(ws_server_connections[i].sock);
			}

			if (ws_server_connections[i].request.header) {
				ws_server_free(ws_server_connections[i].request.header);
			}
			ws_server_connections[i].request.header = NULL;
			if (ws_server_connections[i].response_header) {
				ws_server_free(ws_server_connections[i].response_header);
			}
			ws_server_connections[i].response_header = NULL;
			if (ws_server_connections[i].txbuf) {
				ws_server_free(ws_server_connections[i].txbuf);
			}
			ws_server_connections[i].txbuf = NULL;
			if (ws_server_connections[i].rxbuf) {
				ws_server_free(ws_server_connections[i].rxbuf);
			}
			ws_server_connections[i].rxbuf = NULL;
			if (ws_server_connections[i].receivedData) {
				ws_server_free(ws_server_connections[i].receivedData);
			}
			ws_server_connections[i].receivedData = NULL;
			memset(&ws_server_connections[i], 0, sizeof(ws_conn));
			ws_server_connections[i].sock = -1;
			break;
		}
	}
}

static ws_conn *ws_server_conn_add(int sock)
{
	int i;
	ws_conn *conn = NULL;

	for (i = 0; i < ws_server_max_conn; i ++) {
		if (ws_server_connections[i].sock == -1) {
			ws_server_connections[i].sock = sock;
			ws_server_connections[i].state = CONNECTING;
			conn = &ws_server_connections[i];
			break;
		}
	}

	ws_server_log_verbose("%s add connection %d", __FUNCTION__, sock);
	return conn;
}

static void ws_server_poll(ws_conn *conn)
{
	int ret = 0;
	ret = ws_server_read(conn, &conn->rxbuf[conn->rx_len], (ws_server_rx_size - conn->rx_len) > 1500 ? 1500 : (ws_server_rx_size - conn->rx_len));
	if (ret == 0) {
		return;
	} else if (ret < 0) {
		ws_server_conn_remove(conn);
		ws_server_log("ERROR: Read data failed! %d\n", ret);
		return;
	} else {
		ws_server_log_verbose("\r\nreceiving a message with length : %d from %d\r\n", ret, conn->sock);
		if (ws_server_debug == WS_SERVER_DEBUG_VERBOSE) {
			for (int i = 0; i < ret; i++) {
				printf("%02x ", conn->rxbuf[conn->rx_len + i]);
				if (i % 10 == 0) {
					printf("\r\n");
				}

			}
		}
		conn->rx_len += ret;
	}

	if (conn->rx_len) {
		ws_server_dispatchBinary(conn);
	}

	if (conn->state == CLOSED) {
		return;
	}

	if (conn->tx_len > 0) {
		int remain_len = conn->tx_len;
		do {
			ret = ws_server_write(conn, conn->txbuf + (conn->tx_len - remain_len), (remain_len > 1500 ? 1500 : remain_len));
			if (ret == 0) {
			} else if (ret < 0) {
				ws_server_conn_remove(conn);
				ws_server_log("ERROR: Send data failed!\n");
				return;
			} else {
				ws_server_log_verbose("Send %d bytes data to websocket server\n", ret);
				conn->last_data_comm_time = rtw_get_current_time();
			}
			remain_len -= ret;
		} while (remain_len > 0);

		memset(conn->txbuf, 0, ws_server_tx_size + 16);
		conn->tx_len = 0;
	}

	if (conn->state == CLOSING) {
		ws_server_conn_remove(conn);
	}
	return;
}

static int ws_server_handshake(ws_conn *conn)
{
	int recv_timeout, recv_timeout_backup = 0;
	size_t recv_timeout_len;

	recv_timeout_len = sizeof(recv_timeout_backup);

	if (getsockopt(conn->sock, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout_backup, &recv_timeout_len) != 0) {
		ws_server_log("ERROR: SO_RCVTIMEO");
	}


	recv_timeout = WS_SERVER_RECV_TIMEOUT * 1000;

	if (setsockopt(conn->sock, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout)) != 0) {
		ws_server_log("ERROR: SO_RCVTIMEO");
	}


	if (ws_server_handshake_read_header(conn) == -1) {
		ws_server_response_bad_request(conn, NULL);
		return -1;
	}
	if (setsockopt(conn->sock, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout_backup, sizeof(recv_timeout_backup)) != 0) {
		ws_server_log("ERROR: SO_RCVTIMEO");
	}

	if (ws_server_handshake_response(conn) == -1) {
		return -1;
	}
	conn->state = CONNECTED1;
	ws_server_log("conn %d connected", conn->sock);
	return 0;
}

static void ws_server_conn_thread(void *param)
{
	ws_conn *conn = (ws_conn *) param;
	int ret = -1;
	uint32_t cur_time;

	if (ws_server_conn_init(conn) != 0) {
		ws_server_log("ERROR: ws_server_conn_init failed");
		ws_server_conn_remove(conn);
		rtw_delete_task(&ws_server_conn_tsk);
		return;
	}

	//handshake
	if (conn->state == CONNECTING) {
		union {
			fd_set read_fds;
			char dummy[16];
		} u;
		struct timeval timeout;

		memset(u.dummy, 0, sizeof(u.dummy));

		timeout.tv_sec = ws_server_select_timeout;
		timeout.tv_usec = 0;
		FD_ZERO(&u.read_fds);
		FD_SET(conn->sock, &u.read_fds);
		ws_server_log_verbose("%s conn %d start handshake", __FUNCTION__, conn->sock);
		if (select(conn->sock + 1, &u.read_fds, NULL, NULL, &timeout)) {
			if (FD_ISSET(conn->sock, &u.read_fds)) {
				ret = ws_server_handshake(conn);
				if (ret == -1) {
					ws_server_log("ERROR: ws_server_handshake");
					ws_server_conn_remove(conn);
					rtw_delete_task(&ws_server_conn_tsk);
				} else {
					// update last request time
					conn->last_ping_sent_time = rtw_get_current_time();
					ws_server_log_verbose("%s set last ping sent time:%d", __FUNCTION__, conn->last_ping_sent_time);
					conn->last_data_comm_time = rtw_get_current_time();
					ws_server_log_verbose("%s set last data comm time:%d", __FUNCTION__, conn->last_data_comm_time);
				}
			} else {
				ws_server_log_verbose("%s ERROR: FD_ISSET", __FUNCTION__);
				ws_server_conn_remove(conn);
			}
		} else {
			ws_server_log_verbose("%s handshake select timeout", __FUNCTION__);
			ws_server_conn_remove(conn);
		}
	}
	if (conn->state == CONNECTED1) {
		ws_server_log_verbose("%s conn %d handshake ok, start polling", __FUNCTION__, conn->sock);
		int flag = 1;
		ret = setsockopt(conn->sock, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(flag)); // Disable Nagle's algorithm
		if (ret == 0) {
			ret = fcntl(conn->sock, F_SETFL, O_NONBLOCK);
			if (ret != 0) {
				ws_server_log("ERROR: fcntl O_NONBLOCK");
				ws_server_conn_remove(conn);
				rtw_delete_task(&ws_server_conn_tsk);
			}
		} else {
			ws_server_conn_remove(conn);;
			ws_server_log("ERROR: Failed to set socket option\n");
			rtw_delete_task(&ws_server_conn_tsk);
		}
		conn->last_ping_sent_time = rtw_get_current_time();
		conn->last_data_comm_time = rtw_get_current_time();
		//polling
		while (conn->state != CLOSED) {
			ws_server_poll(conn);
			if (conn->state == CLOSED) {
				ws_server_log("Connection closed");
				break;
			}

			//Check if ping got pong
			if (conn->state == CONNECTED2) {
				cur_time = rtw_get_current_time();
				if ((cur_time - conn->last_ping_sent_time) >= ws_server_ping_interval) {
					ws_server_log("ERROR: did't get pang from client");
					ws_server_conn_remove(conn);
					break;
				}
			} else {
				cur_time = rtw_get_current_time();
				if ((cur_time - conn->last_ping_sent_time) >= ws_server_ping_interval) {
					ws_server_sendPing(conn);
					ws_server_log_verbose("Send ping to conn(%d) at %d", conn->sock, cur_time);
					conn->last_ping_sent_time = cur_time;
				}
			}

			if (ws_server_idle_timeout != 0) {
				cur_time = rtw_get_current_time();
				if ((cur_time - conn->last_data_comm_time) >= ws_server_idle_timeout) {
					ws_server_log("conn(%d) timeout", conn->sock);
					ws_server_conn_remove(conn);
					break;
				}
			}
		}
	}

	ws_server_log_verbose("%s stopped", __FUNCTION__);
	rtw_delete_task(&ws_server_conn_tsk);
}

static void ws_server_thread(void *param)
{
	/* To avoid gcc warnings */
	(void) param;

	ws_server_log_verbose("%s started", __FUNCTION__);
	ws_server_running = 1;

	while (ws_server_running) {
		union {
			fd_set read_fds;
			char dummy[16];
		} u;
		struct timeval timeout;

		memset(u.dummy, 0, sizeof(u.dummy));

		timeout.tv_sec = ws_server_select_timeout;
		timeout.tv_usec = 0;
		FD_ZERO(&u.read_fds);
		FD_SET(ws_server_sock, &u.read_fds);

		if (select(ws_server_max_sock + 1, &u.read_fds, NULL, NULL, &timeout)) {
			if (FD_ISSET(ws_server_sock, &u.read_fds)) {
				struct sockaddr_in client_addr;
				unsigned int client_addr_size = sizeof(client_addr);
				int client_sock;
				ws_conn *conn = NULL;

				if ((client_sock = accept(ws_server_sock, (struct sockaddr *) &client_addr, &client_addr_size)) >= 0) {
					ws_server_log_verbose("accept(%d)", client_sock);
					conn = ws_server_conn_add(client_sock);

					if (conn == NULL) {
						ws_conn tmp_conn;

						ws_server_log("ERROR: ws_server_conn_add");
						memset(&tmp_conn, 0, sizeof(ws_conn));
						tmp_conn.sock = client_sock;

						if (ws_server_secure) {
							tmp_conn.tls = (void *)ws_server_tls_new_handshake(&tmp_conn.sock, ws_server_secure);

							if (tmp_conn.tls == NULL) {
								ws_server_log("ERROR: ws_server_tls_new_handshake");
								close(client_sock);
								continue;
							}
						}

						ws_server_response_too_many_requests(&tmp_conn, NULL);

						if (tmp_conn.tls) {
							ws_server_tls_close(tmp_conn.tls);
							ws_server_tls_free(tmp_conn.tls);
						}

						close(client_sock);
					} else {
						// enable socket keepalive with keepalive timeout = idle(3) + interval(5) * count(3) = 18 seconds
						int keepalive = 1, keepalive_idle = 3, keepalive_interval = 5, keepalive_count = 3;

						if (setsockopt(conn->sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) != 0) {
							ws_server_log("ERROR: SO_KEEPALIVE");
						}
						if (setsockopt(conn->sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_idle, sizeof(keepalive_idle)) != 0) {
							ws_server_log("ERROR: TCP_KEEPIDLE");
						}
						if (setsockopt(conn->sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_interval, sizeof(keepalive_interval)) != 0) {
							ws_server_log("ERROR: TCP_KEEPINTVL");
						}
						if (setsockopt(conn->sock, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_count, sizeof(keepalive_count)) != 0) {
							ws_server_log("ERROR: TCP_KEEPCNT");
						}
						// set conn ssl
						if (ws_server_secure) {
							conn->tls = (void *)ws_server_tls_new_handshake(&conn->sock, ws_server_secure);

							if (conn->tls == NULL) {
								ws_server_log("ERROR: ws_server_tls_new_handshake");
								ws_server_conn_remove(conn);
							}
						}

						// update max sock for select
						if (client_sock > ws_server_max_sock) {
							ws_server_max_sock = client_sock;
						}

						if (rtw_create_task(&ws_server_conn_tsk,  "ws_server_conn", ws_server_stack_bytes / 4,  WS_SERVER_PRIORITY, ws_server_conn_thread, conn) != 1) {
							ws_server_log("ERROR: xTaskCreate ws_server_conn");
							ws_server_conn_remove(conn);
						}
					}
				} else {
					ws_server_log("ERROR: accept");
					goto exit;
				}
			}
		}
	}
exit:
	ws_server_deinit();
	ws_server_log("%s stopped", __FUNCTION__);
	ws_server_running = 0;
	rtw_delete_task(&ws_server_tsk);
}

int ws_server_start(uint16_t port, uint8_t max_conn, uint32_t stack_bytes, uint8_t secure)
{
	ws_server_setup(port, max_conn, secure);
	if (stack_bytes > 0) {
		ws_server_stack_bytes = stack_bytes;
	}

	if (ws_server_init()) {
		ws_server_log("ERROR: ws_server_init");
		return -1;
	}
	if (rtw_create_task(&ws_server_tsk, "ws_server", ws_server_stack_bytes / 4, WS_SERVER_PRIORITY, ws_server_thread, NULL) != 1) {
		ws_server_log("ERROR: xTaskCreate ws_server");
		ws_server_deinit();
		return -1;
	}
	return 0;
}

void ws_server_stop(void)
{
	ws_server_running = 0;
}

void ws_server_setup_debug(uint8_t debug)
{
	ws_server_debug = debug;
}

int ws_server_setup_cert(const char *server_cert, const char *server_key, const char *ca_certs)
{
	return ws_server_tls_setup_init(server_cert, server_key, ca_certs);
}

void ws_server_setup_ping_interval(int interval_ms)
{
	ws_server_ping_interval = interval_ms;
}

void ws_server_setup_idle_timeout(int timeout_ms)
{
	ws_server_idle_timeout = timeout_ms;
}

void ws_server_setup_tx_rx_size(size_t tx_size, size_t rx_size)
{
	ws_server_tx_size = tx_size;
	ws_server_rx_size = rx_size;
}

void ws_server_print_status(void)
{
	if (ws_server_connections) {
		int i;
		for (i = 0; i < ws_server_max_conn; i ++) {
			if (ws_server_connections[i].sock != -1) {
				printf("\n\r==============================");
				printf("\n\r\tSOCKET => %d", ws_server_connections[i].sock);
				printf("\n\r\tSTATUS => ");
				switch (ws_server_connections[i].state) {
				case CLOSED:
					printf("CLOSED\r\n");
					break;
				case CONNECTING:
					printf("CONNECTING\r\n");
					break;
				case CONNECTED1:
					printf("CONNECTED\r\n");
					break;
				case CONNECTED2:
					printf("CONNECTED-PINGSENT\r\n");
					break;
				case CLOSING:
					printf("CLOSING\r\n");
					break;
				default:
					printf("UNKNOWN STATUS\r\n");
					break;
				}

			}
		}
	} else {
		printf("\r\n[WS_SERVER]: Didn't init server\r\n");
	}
}

ws_conn *ws_server_get_conn_info(int conn_no)
{
	if (ws_server_connections) {
		if (conn_no < ws_server_max_conn) {
			return &ws_server_connections[conn_no];
		} else {
			ws_server_log("ERROR: conn_no should be small than ws_server_max_conn");
			return NULL;
		}
	} else {
		ws_server_log("ERROR: There is no connections");
		return NULL;
	}
}

