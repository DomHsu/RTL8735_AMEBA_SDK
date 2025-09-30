#include <lwip/netdb.h>
#include <lwip/sockets.h>
#include <stdio.h>
#include <string.h>
#include <websocket/wsclient_api.h>

void (*ws_receive_cb)(wsclient_context **, int) = NULL;
int max_data_len = 0;
uint32_t wsclient_keepalive_idle = 0;
uint32_t wsclient_keepalive_interval = 0;
uint32_t wsclient_keepalive_count = 0;
uint32_t wsclient_recvtimeout = 0;
uint32_t wsclient_sendtimeout = 0;

static void ws_dispatchBinary(wsclient_context **wsclient)
{
	wsclient_context *wsc = *wsclient;
	while (1) {
		struct wsheader_type ws;
		if (wsc->rx_len < 2) {
			return;
		}
		const uint8_t *data = (uint8_t *) &wsc->rxbuf[0];  // peek, but don't consume
		ws.fin = (data[0] & 0x80) == 0x80;
		wsc->rxRsvBits.RSV1 = (data[0] & 0x40) >> 6;
		wsc->rxRsvBits.RSV2 = (data[0] & 0x20) >> 5;
		wsc->rxRsvBits.RSV3 = (data[0] & 0x10) >> 4;
		ws.opcode = (data[0] & 0x0f);
		ws.mask = (data[1] & 0x80) == 0x80;
		ws.N0 = (data[1] & 0x7f);
		ws.header_size = 2 + (ws.N0 == 126 ? 2 : 0) + (ws.N0 == 127 ? 8 : 0) + (ws.mask ? 4 : 0);
		if (wsc->rx_len < ws.header_size) {
			return;
		}
		int i = 0;
		if (ws.N0 < 126) {
			ws.N = ws.N0;
			i = 2;
		} else if (ws.N0 == 126) {
			ws.N = 0;
			ws.N |= ((uint64_t) data[2]) << 8;
			ws.N |= ((uint64_t) data[3]) << 0;
			i = 4;
		} else if (ws.N0 == 127) {
			ws.N = 0;
			ws.N |= ((uint64_t) data[2]) << 56;
			ws.N |= ((uint64_t) data[3]) << 48;
			ws.N |= ((uint64_t) data[4]) << 40;
			ws.N |= ((uint64_t) data[5]) << 32;
			ws.N |= ((uint64_t) data[6]) << 24;
			ws.N |= ((uint64_t) data[7]) << 16;
			ws.N |= ((uint64_t) data[8]) << 8;
			ws.N |= ((uint64_t) data[9]) << 0;
			i = 10;
		}
		if (ws.mask) {
			ws.masking_key[0] = ((uint8_t) data[i + 0]) << 0;
			ws.masking_key[1] = ((uint8_t) data[i + 1]) << 0;
			ws.masking_key[2] = ((uint8_t) data[i + 2]) << 0;
			ws.masking_key[3] = ((uint8_t) data[i + 3]) << 0;
		} else {
			ws.masking_key[0] = 0;
			ws.masking_key[1] = 0;
			ws.masking_key[2] = 0;
			ws.masking_key[3] = 0;
		}
		if (wsc->rx_len < ws.header_size + ws.N) {
			if (ws.header_size + ws.N > max_data_len) {
				WSCLIENT_ERROR("Got message size exceed the max buf %d, %d\n", ws.header_size + ws.N, max_data_len);
			}
			return; /* Need: ws.header_size+ws.N - rxbuf.size() */
		}

		// We got a whole message, now do something with it:
		if (ws.opcode == TEXT_FRAME || ws.opcode == BINARY_FRAME || ws.opcode == CONTINUATION) {
			if (ws.mask) {
				for (size_t i = 0; i != ws.N; ++i) {
					wsc->rxbuf[i + ws.header_size] ^= ws.masking_key[i & 0x3];
				}
			}
			memset(wsc->receivedData, 0, max_data_len);
			memcpy(wsc->receivedData, (wsc->rxbuf + ws.header_size), ws.N);

			if (ws.fin != 0) {
				if (ws_receive_cb != NULL) {
					ws_receive_cb(wsclient, ws.N);
				}
			}
		} else if (ws.opcode == PING) {
			if (ws.mask) {
				for (size_t i = 0; i != ws.N; ++i) {
					wsc->rxbuf[i + ws.header_size] ^= ws.masking_key[i & 0x3];
				}
			}
			WSCLIENT_DEBUG("Get PING from server with payload length %d\n", ws.N);
			if (ws.N > 0) {
				ws_sendData(PONG, ws.N, &wsc->rxbuf[ws.header_size], 1, wsc);
			} else {
				ws_sendData(PONG, 0, NULL, 1, wsc);
			}
		} else if (ws.opcode == PONG) { }
		else if (ws.opcode == CLOSE) {
			ws_close(wsclient);
		} else {
			WSCLIENT_ERROR("ERROR: Got unexpected WebSocket message.\n");
			wsc->fun_ops.client_close(wsc);
			//*wsclient = NULL;
			//should return, otherwise while loop will parse rxbuf continuesly, while rxbuf
			//has been free in client_close
			return;
		}

		wsc->rx_len = wsc->rx_len - (ws.header_size + ws.N);
		// If still got content, move it to the front of rxbuf
		if (wsc->rx_len > 0) {
			memmove(wsc->rxbuf, (wsc->rxbuf + ws.header_size + ws.N), wsc->rx_len);
		}
	}
}

int wss_set_fun_ops(wsclient_context *wsclient)
{
	struct ws_fun_ops *ws_fun = &wsclient->fun_ops;
	if (wsclient->use_ssl == 1) {
		ws_fun->hostname_connect = &wss_hostname_connect;
		ws_fun->client_close = &wss_client_close;
		ws_fun->client_read = &wss_client_read;
		ws_fun->client_send = &wss_client_send;
	} else {
		ws_fun->hostname_connect = &ws_hostname_connect;
		ws_fun->client_close = &ws_client_close;
		ws_fun->client_read = &ws_client_read;
		ws_fun->client_send = &ws_client_send;
	}
	return 0;
}

int ws_set_fun_ops(wsclient_context *wsclient)
{
	struct ws_fun_ops *ws_fun = &wsclient->fun_ops;

	if (wsclient->use_ssl == 0) {
		ws_fun->hostname_connect = &ws_hostname_connect;
		ws_fun->client_close = &ws_client_close;
		ws_fun->client_read = &ws_client_read;
		ws_fun->client_send = &ws_client_send;
		return 0;
	} else {
		WSCLIENT_ERROR("ERROR: Didn't define the USING_SSL\n");
		return -1;
	}
}

void ws_close(wsclient_context **wsclient)
{
	wsclient_context *wsc = *wsclient;
	if (wsc->readyState == WSCLOSING || wsc->readyState == WSCLOSED || wsclient == NULL) {
		return;
	}
	wsc->readyState = WSCLOSING;
	uint8_t pong_Frame[6] = {0x88, 0x80, 0x00, 0x00, 0x00, 0x00};
	wsc->fun_ops.client_send(wsc, pong_Frame, 6);
//	wsc->fun_ops.client_close(wsc);
//	*wsclient = NULL;	//To fix the ws_getReadyState() after ws_close() faied issue, then free the context in the example
	printf("\r\n\r\n\r\n>>>>>>>>>>>>>>>Closing the Connection with websocket server<<<<<<<<<<<<<<<<<<\r\n\r\n\r\n");
}

readyStateValues ws_getReadyState(wsclient_context *wsclient)
{
	return wsclient->readyState;
}

void ws_dispatch(void (*callback)(wsclient_context **, int))
{
	ws_receive_cb = callback;
}

void ws_poll(int timeout, wsclient_context **wsclient)   // timeout in milliseconds
{
	int ret = 0;
	send_buf *tmp_buf = NULL;
	wsclient_context *wsc = *wsclient;

	if (wsc->readyState == WSCLOSED) {
		if (timeout > 0) {
			struct timeval tv = { timeout / 1000, (timeout % 1000) * 1000 };
			select(0, NULL, NULL, NULL, &tv);
		}
		return;
	}
	if (timeout != 0) {
		union {
			fd_set rfds;
			char dummy[16];
		} u_r;
		union {
			fd_set wfds;
			char dummy[16];
		} u_w;
		struct timeval tv = { timeout / 1000, (timeout % 1000) * 1000 };

		memset(u_r.dummy, 0, sizeof(u_r.dummy));
		memset(u_w.dummy, 0, sizeof(u_w.dummy));

		FD_ZERO(&u_r.rfds);
		FD_ZERO(&u_w.wfds);
		FD_SET(wsc->sockfd, &u_r.rfds);
		if (rtw_peek_from_xqueue(&wsc->ready_send_buf, (void *)&tmp_buf, 0) == SUCCESS) {
			if (tmp_buf->tx_len > 0) {
				FD_SET(wsc->sockfd, &u_w.wfds);
			}
		}
		ret = select(wsc->sockfd + 1, &u_r.rfds, &u_w.wfds, 0, timeout > 0 ? &tv : 0);
		if (ret == 0) {
			WSCLIENT_DEBUG("Polling timeout!\n", ret);
			return;
		} else if (ret < 0) {
			wsc->fun_ops.client_close(wsc);
			//*wsclient = NULL;
			WSCLIENT_ERROR("ERROR: Select error! ret = %d\n", ret);
			return;
		}

	}

	while (1) {
		ret = wsc->fun_ops.client_read(wsc, &wsc->rxbuf[wsc->rx_len], (max_data_len - wsc->rx_len) > 1500 ? 1500 : (max_data_len - wsc->rx_len));
		if (ret == 0) {
			break;
		} else if (ret < 0) {
			closesocket(wsc->sockfd);
			wsc->fun_ops.client_close(wsc);
			//*wsclient = NULL;
			WSCLIENT_ERROR("ERROR: Read data failed!\n");
			//should return, otherwise ws_dispatchBinary will parse rxbuf continuesly, while rxbuf
			//has been free in client_close
			return;
		} else {
			WSCLIENT_DEBUG("\r\nreceiving the message with length : %d\r\n", ret);
			wsc->rx_len += ret;
		}
	}
	ws_dispatchBinary(wsclient);

	if (*wsclient == NULL) {
		return;
	}

//send buffer in ready queue
	if (rtw_pop_from_xqueue(&wsc->ready_send_buf, (void *)&tmp_buf, 0) == SUCCESS) {
		wsc->ready_send_buf_num--;
		WSCLIENT_DEBUG("receiving message buffer from ready queue\r\n");
		if (tmp_buf->tx_len > 0) {
			int remain_len = tmp_buf->tx_len;
			do {
				if (*wsclient == NULL) {
					return;
				}
				ret = wsc->fun_ops.client_send(wsc, tmp_buf->txbuf + (tmp_buf->tx_len - remain_len), (remain_len > 1500 ? 1500 : remain_len));
				if (ret == 0) {
				} else if (ret < 0) {
					rtw_push_to_xqueue(&wsc->recycle_send_buf, (void *)&tmp_buf, RTW_WAIT_FOREVER);
					wsc->recycle_send_buf_num++;
					closesocket(wsc->sockfd);
					wsc->fun_ops.client_close(wsc);
					//*wsclient = NULL;
					WSCLIENT_ERROR("ERROR: Send data faild!\n");
					return;
				} else {
					WSCLIENT_DEBUG("Send %d bytes data to websocket server\r\n", ret);
				}
				remain_len -= ret;
			} while (remain_len > 0);

			memset(tmp_buf->txbuf, 0, max_data_len + 16);
			tmp_buf->tx_len = 0;
		}

		//If free buffers exceed the stable buffer number, it will be dynamically free.
		//Else, it wil be pushed back to recycle queue.
		if (wsc->recycle_send_buf_num >= wsc->stable_buf_num) {
			if (tmp_buf) {
				if (tmp_buf->txbuf) {
					ws_free(tmp_buf->txbuf);
				}
				tmp_buf->tx_len = 0;
				ws_free(tmp_buf);
				WSCLIENT_DEBUG("Buffer is enough. Recycle after polling");
			}
		} else {
			rtw_push_to_xqueue(&wsc->recycle_send_buf, (void *)&tmp_buf, 0xFFFFFFFF);
			wsc->recycle_send_buf_num++;
			WSCLIENT_DEBUG("send back buffer to recycle queue\r\n");
		}
	}
	WSCLIENT_DEBUG("ready_send_buf num: %d, recycle_send_buf num: %d\r\n", wsc->ready_send_buf_num, wsc->recycle_send_buf_num);

	if (wsc->readyState == WSCLOSING && rtw_peek_from_xqueue(&wsc->ready_send_buf, (void *)&tmp_buf, 0) != SUCCESS) {
		closesocket(wsc->sockfd);
		wsc->fun_ops.client_close(wsc);
	}

}

int ws_sendPing(int use_mask, wsclient_context *wsclient)
{
	int ret = 0;
	ret = ws_sendData(PING, 0, NULL, use_mask, wsclient);
	return ret;
}

int ws_sendBinary(uint8_t *message, int message_len, int use_mask, wsclient_context *wsclient)
{
	int ret = 0;
	if (message_len > max_data_len) {
		WSCLIENT_ERROR("ERROR: The length of data exceeded the tx buf len: %d\n", max_data_len);
		return -1;
	}
	ret = ws_sendData(BINARY_FRAME, message_len, (uint8_t *)message, use_mask, wsclient);
	return ret;
}

int ws_send(char *message, int message_len, int use_mask, wsclient_context *wsclient)
{
	int ret = 0;
	WSCLIENT_DEBUG("Send data: %s\n", message);
	if (message_len > max_data_len) {
		WSCLIENT_ERROR("ERROR: The length of data exceeded the tx buf len: %d\n", max_data_len);
		return -1;
	}
	ret = ws_sendData(TEXT_FRAME, message_len, (uint8_t *)message, use_mask, wsclient);
	return ret;
}

int ws_connect_url(wsclient_context *wsclient)
{
	int ret;

	ret = wsclient->fun_ops.hostname_connect(wsclient);
	if (ret == -1) {
		wsclient->fun_ops.client_close(wsclient);
		return -1;
	} else {
		ret = ws_client_handshake(wsclient);
		if (ret <= 0) {
			WSCLIENT_ERROR("ERROR: Sending handshake failed\n");
			wsclient->fun_ops.client_close(wsclient);
			return -1;
		} else {
			ret = ws_check_handshake(wsclient);
			if (ret == 0) {
				WSCLIENT_DEBUG("Connected with websocket server!\n");
			} else {
				WSCLIENT_ERROR("ERROR: Response header is wrong\n");
				wsclient->fun_ops.client_close(wsclient);
				return -1;
			}
		}
	}

	int flag = 1;
	ret = setsockopt(wsclient->sockfd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(flag)); // Disable Nagle's algorithm
	if (ret == 0) {
		ret = fcntl(wsclient->sockfd, F_SETFL, O_NONBLOCK);
		if (ret == 0) {
			wsclient->readyState = WSOPEN;
			printf("\r\n\r\n\r\n>>>>>>>>>>>>>>>Connected to websocket server<<<<<<<<<<<<<<<<<<\r\n\r\n\r\n");
			return wsclient->sockfd;
		} else {
			wsclient->fun_ops.client_close(wsclient);
			return -1;
		}
	} else {
		wsclient->fun_ops.client_close(wsclient);
		WSCLIENT_ERROR("ERROR: Failed to set socket option\n");
		return -1;
	}
}

void ws_setsockopt_keepalive(uint32_t keepalive_idle, uint32_t keepalive_interval, uint32_t keepalive_count)
{
	wsclient_keepalive_idle = keepalive_idle;
	wsclient_keepalive_interval = keepalive_interval;
	wsclient_keepalive_count = keepalive_count;
}

void ws_setsockopt_timeout(uint32_t recv_timeout, uint32_t send_timeout)
{
	wsclient_recvtimeout = recv_timeout;
	wsclient_sendtimeout = send_timeout;
}

int ws_handshake_header_set_protocol(wsclient_context *wsclient, char *pro, int len)
{
	if (wsclient && pro && len > 0) {
		wsclient->protocol = (char *) ws_malloc(len + 1);
		if (wsclient->protocol == NULL) {
			WSCLIENT_ERROR("ERROR: Malloc(%d bytes) failed\n", len + 1);
			return -1;
		}

		wsclient->protocol_len = len;
		rtw_memcpy(wsclient->protocol, pro, len);
		return 0;
	} else {
		WSCLIENT_ERROR("ERROR: Failed to set header protocol\n");
		return -1;
	}
}

int ws_handshake_header_set_version(wsclient_context *wsclient, char *ver, int len)
{
	if (wsclient && ver && len > 0) {
		wsclient->version = (char *) ws_malloc(len + 1);
		if (wsclient->version == NULL) {
			WSCLIENT_ERROR("ERROR: Malloc(%d bytes) failed\n", len + 1);
			return -1;
		}

		wsclient->version_len = len;
		rtw_memcpy(wsclient->version, ver, len);
		return 0;
	} else {
		WSCLIENT_ERROR("ERROR: Failed to set header version\n");
		return -1;
	}
}

int ws_handshake_header_custom_token(wsclient_context *wsclient, char *cus, int len)
{
	if (wsclient && cus && len > 0) {
		wsclient->custom_token = (char *) ws_malloc(len + 1);
		if (wsclient->custom_token == NULL) {
			WSCLIENT_ERROR("ERROR: Malloc(%d bytes) failed\n", len + 1);
			return -1;
		}

		wsclient->custom_token_len = len;
		rtw_memcpy(wsclient->custom_token, cus, len);
		return 0;
	} else {
		WSCLIENT_ERROR("ERROR: Failed to set header custom token\n");
		return -1;
	}
}

int ws_multisend_opts(wsclient_context *wsclient, int stable_buf_num)
{
	if (!wsclient) {
		WSCLIENT_ERROR("ERROR: Please create wsclient before calling ws_multisend_opts\n");
		return -1;
	}
	if (stable_buf_num < 0 || stable_buf_num > wsclient->max_queue_size) {
		WSCLIENT_ERROR("ERROR: stable_buf_num should be positive value and not exceed %d(max_queue_size)\n", wsclient->max_queue_size);
		return -1;
	}
	wsclient->stable_buf_num = stable_buf_num;
	WSCLIENT_DEBUG("stable_buf_num set to %d successfully\r\n", stable_buf_num);

	return 0;
}

wsclient_context *create_wsclient(char *url, int port, char *path, char *origin, int buf_len, int max_queue_size)
{

	int i;
	const int initial_item_num = 1;
	send_buf *tmp_buf = NULL;
	size_t url_len = 0;

	wsclient_context *wsclient = (wsclient_context *)ws_malloc(sizeof(wsclient_context));
	if (wsclient == NULL) {
		WSCLIENT_ERROR("ERROR: Malloc(%d bytes) failed\n", sizeof(wsclient_context));
		return NULL;
	}

	max_data_len = buf_len;

	wsclient->port = port;

	if (origin == NULL) {
		wsclient->origin = NULL;
	} else {
		wsclient->origin = (char *)ws_malloc(sizeof(char) * (strlen(origin) + 1));
		if (!wsclient->origin) {
			WSCLIENT_ERROR("ERROR: Malloc(%d bytes) failed\n", strlen(origin) + 1);
			goto create_wsclient_fail;
		}

		memcpy(wsclient->origin, origin, strlen(origin));
	}

	if (strlen(url) >= DNS_MAX_NAME_LENGTH) {
		WSCLIENT_ERROR("ERROR: Url size exceeded\n");
		goto create_wsclient_fail;
	}

	wsclient->host = NULL;
	wsclient->path = NULL;

	if (path) {
		wsclient->path = (char *)ws_malloc(sizeof(char) * (strlen(path) + 1));
		if (!wsclient->path) {
			ws_free(wsclient->origin);
			wsclient->origin = NULL;
			WSCLIENT_ERROR("ERROR: Malloc(%d bytes) failed\n", strlen(path) + 1);
			goto create_wsclient_fail;
		}

		memcpy(wsclient->path, path, strlen(path));
	}

	if (!strncmp(url, "wss://", strlen("wss://")) || !strncmp(url, "WSS://", strlen("WSS://"))) {
		url_len = strlen(url) - strlen("wss://");
	} else {
		url_len = strlen(url) - strlen("ws://");
	}

	wsclient->host = (char *)ws_malloc(sizeof(char) * (url_len + 1));
	if (!wsclient->host) {
		ws_free(wsclient->origin);
		wsclient->origin = NULL;
		ws_free(wsclient->path);
		wsclient->path = NULL;
		WSCLIENT_ERROR("ERROR: Malloc(%d bytes) failed\n", url_len + 1);
		goto create_wsclient_fail;
	}

	if (!strncmp(url, "wss://", strlen("wss://")) || !strncmp(url, "WSS://", strlen("WSS://"))) {
		memcpy(wsclient->host, (url + strlen("wss://")), (strlen(url) - strlen("wss://")));
		wsclient->use_ssl = 1;
		if (wsclient->port <= 0) {
			wsclient->port = 443;
		}
	} else if (!strncmp(url, "ws://", strlen("ws://")) || !strncmp(url, "WS://", strlen("WS://"))) {
		memcpy(wsclient->host, (url + strlen("ws://")), (strlen(url) - strlen("ws://")));
		wsclient->use_ssl = 0;
		if (wsclient->port <= 0) {
			wsclient->port = 80;
		}
	} else {
		WSCLIENT_ERROR("ERROR: Url format is wrong: %s\n", url);
		goto create_wsclient_fail;
	}

	wsclient->protocol = NULL;
	wsclient->protocol_len = 0;
	wsclient->version = NULL;
	wsclient->version_len = 0;
	wsclient->custom_token = NULL;
	wsclient->custom_token_len = 0;

	wsclient->readyState = WSCLOSED;
	wsclient->sockfd = -1;
	wsclient->tx_len = 0;
	wsclient->rx_len = 0;
	wsclient->tls = NULL;

	//create queue for tx
	if (max_queue_size <= 0) {
		WSCLIENT_ERROR("ERROR: Queue size must larger than 0: \r\n");
		goto create_wsclient_fail;
	}
	wsclient->max_queue_size = max_queue_size;
	wsclient->stable_buf_num = max_queue_size; //set to max buffer num. default not enable buffer recycle mechenism
	wsclient->ready_send_buf_num = 0;
	wsclient->recycle_send_buf_num = 0;
	wsclient->ready_send_buf = NULL;
	wsclient->recycle_send_buf = NULL;

	rtw_init_xqueue(&wsclient->ready_send_buf, "ready_send_buf_queue", sizeof(send_buf *), max_queue_size);
	rtw_init_xqueue(&wsclient->recycle_send_buf, "recycle_send_buf_queue", sizeof(send_buf *), max_queue_size);
	if (wsclient->ready_send_buf == NULL || wsclient->recycle_send_buf == NULL) {
		WSCLIENT_ERROR("ERROR: Send_buf queue malloc fail\n\r");
		goto create_wsclient_fail;
	}

	// initialize 1 queue item
	// the rest of queue item will be increased in ws_sendData if queue item is not enough -Raymond Lee
	for (i = 0; i < initial_item_num; i++) {
		if (i + 1 > max_queue_size) {
			break;
		}
		tmp_buf = ws_malloc(sizeof(send_buf));
		if (!tmp_buf) {
			WSCLIENT_ERROR("ERROR: Send_buf malloc fail\n\r");
			goto create_wsclient_fail;
		}

		WSCLIENT_DEBUG("Create queue item: %x\r\n", tmp_buf);

		tmp_buf->txbuf = (uint8_t *)ws_malloc(max_data_len + 16);
		if (!tmp_buf->txbuf) {
			WSCLIENT_ERROR("ERROR: Send_buf txbuf malloc fail\n\r");
			ws_free(tmp_buf);
			goto create_wsclient_fail;
		}

		WSCLIENT_DEBUG("Create buffer of queue item: %x\r\n", tmp_buf->txbuf);

		if (rtw_push_to_xqueue(&wsclient->recycle_send_buf, (void *)&tmp_buf, RTW_WAIT_FOREVER) != SUCCESS) {
			WSCLIENT_ERROR("ERROR: Send_buf queue send fail\n\r");
			ws_free(tmp_buf->txbuf);
			ws_free(tmp_buf);
			goto create_wsclient_fail;
		}
		wsclient->recycle_send_buf_num++;
	}

	wsclient->txbuf = (uint8_t *)ws_malloc(max_data_len + 16);
	wsclient->rxbuf = (uint8_t *)ws_malloc(max_data_len + 16);
	wsclient->receivedData = (uint8_t *)ws_malloc(max_data_len);

	if (!wsclient->txbuf || !wsclient->rxbuf || !wsclient->receivedData) {
		WSCLIENT_ERROR("ERROR: Malloc tx rx buffer memory fail\n");
		goto create_wsclient_fail;
	}

	wsclient->txRsvBits.RSV1 = 0;
	wsclient->txRsvBits.RSV2 = 0;
	wsclient->txRsvBits.RSV3 = 0;

	wsclient->rxRsvBits.RSV1 = 0;
	wsclient->rxRsvBits.RSV2 = 0;
	wsclient->rxRsvBits.RSV3 = 0;


	if (wsclient_set_fun_ops(wsclient) < 0) {
		WSCLIENT_ERROR("ERROR: Init function failed\n");
		goto create_wsclient_fail;
	}

	return wsclient;

create_wsclient_fail:
	ws_client_close(wsclient);
	if (wsclient) {
		ws_free(wsclient);
	}
	return NULL;

}
