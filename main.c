#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <getopt.h>
#include <errno.h>
#include <locale.h>
#ifndef WIN32
#include <netinet/in.h>
#endif

#include <sodium/utils.h>
#include <tox/tox.h>
 
#include <glib.h>
#include <gio/gio.h>

#include <nice/pseudotcp.h>

#define CONVERSATION_NUM_CMD     0xC8000000

#define CONVERSATION_NUM_BEGIN   0xC8000001
#define CONVERSATION_NUM_END     0xFEFFFFFF

#define SOURCE_PORT_BEGIN   0xC800
#define SOURCE_PORT_END     0xFEFF

#define STANDBY_TIMEOUT 5ull*1000ull*1000ull
#define TIME_WAIT_INTERVAL 4ull*60ull*1000ull

#define MTU_VIA_TOX 1280

struct app_data
{
	Tox* tox;
	uint32_t tox_iterate_interval;
	uint64_t last_tox_activity_time;
	int create;
	char tox_file[256];
	uint8_t friend_pubkey[TOX_PUBLIC_KEY_SIZE];
	int usage_only;
	int add_friend;
	int del_friend;
	int promiscuous;
	int server_mode;
	int client_mode;
	uint16_t mtu;

	GSList* acceptor_list;
	GSList* connection_list;
};

struct connection_data
{
	struct app_data* app;
	uint32_t friend_number;
	uint32_t conversation;
	GSocketConnection* socket_connection;
	PseudoTcpSocket* pseudotcp_socket;
	PseudoTcpCallbacks pseudotcp_callbacks;
	unsigned int pseudotcp_clock;

	char tox2tcp_buf[MTU_VIA_TOX];
	int tox2tcp_begin;
	int tox2tcp_end;
	int tox2tcp_stat;

	char tcp2tox_buf[MTU_VIA_TOX];
	int tcp2tox_begin;
	int tcp2tox_end;
	int tcp2tox_stat;
};

struct acceptor_data
{
	struct app_data* app;
	uint32_t friend_number;
	uint32_t conversation_counter;
	uint16_t local_port;
	uint16_t remote_port;
};

GMainLoop* mainloop = NULL;

static void adjust_clock(struct connection_data* cd);
static void outgoing_connected(GObject* source_object, GAsyncResult* res, gpointer user_data);
static gboolean incoming_connected(GSocketService* service, GSocketConnection* connection, GObject* source_object, gpointer user_data);
static struct connection_data* create_connection_data(struct app_data* app, uint32_t friend_number, uint32_t conversation);
static void free_connection_data(struct connection_data* cd);

static void signal_handler(int sig)
{
	switch (sig)
	{
		case SIGINT:
		case SIGTERM:
			g_main_loop_quit(mainloop);
			break;
		default:
			fprintf(stderr, "Unknown signal %d\n", sig);
	}
}

static void print_usage(void)
{
	fprintf(stderr, "Usage: toxconnect -n -t <tox_file>\n");
	fprintf(stderr, "       toxconnect -f <tox_address>|<public_key> -t <tox_file>\n");
	fprintf(stderr, "       toxconnect -d <tox_address>|<public_key> -t <tox_file>\n");
	fprintf(stderr, "       toxconnect -c <local_port>:<friend_number>:<remote_port> -t <tox_file>\n");
	fprintf(stderr, "       toxconnect -s -t <tox_file>\n");
	fprintf(stderr, "       toxconnect -t <tox_file>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "	-t, --file      Tox file\n");
	fprintf(stderr, "	-n, --new       Create new tox file and exit\n");
	fprintf(stderr, "	-f, --friend    Add a friend to the tox file and exit\n");
	fprintf(stderr, "	-d, --delete    Delete a friend from the tox file and exit\n");
	fprintf(stderr, "	-h, --help      Show this help and exit\n");
	fprintf(stderr, "	-c, --client    Listen for incoming client connections on the specified port and trasfer data to remote port of a friend\n");
	fprintf(stderr, "	-s, --server    Start in server mode\n");
	fprintf(stderr, "\n");
}

static bool parse_pubkey(uint8_t* pubkey, const char* str, int str_len)
{
	if (str_len != TOX_ADDRESS_SIZE * 2 && str_len != TOX_PUBLIC_KEY_SIZE * 2)
	{
		return false;
	}

	return sodium_hex2bin(pubkey, TOX_PUBLIC_KEY_SIZE, str, TOX_PUBLIC_KEY_SIZE * 2, NULL, NULL, NULL) == 0;
}

static struct app_data* create_app_data(int argc, char *argv[])
{
	static struct option long_opts[] = {
		{"tox", required_argument, 0, 't'},
		{"new", no_argument, 0, 'n'},
		{"friend", required_argument, 0, 'f'},
		{"delete", required_argument, 0, 'd'},
		{"help", no_argument, 0, 'h'},
		{"client", required_argument, 0, 'c'},
		{"server", required_argument, 0, 's'},
		{"promiscuous", no_argument, 0, 'p'},
		{NULL, no_argument, NULL, 0},
	};

	const char *opts_str = "t:nf:d:hc:sp";
	int opt, indexptr;
	uint16_t local_port;
	uint16_t remote_port;
	uint32_t friend_number;
	struct acceptor_data* ad;
	char* pch;

	struct app_data* app = (struct app_data*)malloc(sizeof(struct app_data));
	memset(app, 0, sizeof(struct app_data));

	app->mtu = MTU_VIA_TOX;

	while ((opt = getopt_long(argc, argv, opts_str, long_opts, &indexptr)) != -1)
	{
		int optarg_len = optarg ? strlen(optarg) : 0;
		switch (opt)
		{
			case 'n':
				app->create = 1;
				break;

			case 't':
				snprintf(app->tox_file, sizeof(app->tox_file), "%s", optarg);
				break;

			case 'f':
				if (!parse_pubkey(app->friend_pubkey, optarg, optarg_len))
				{
					fprintf(stderr, "Valid tox address or public key required\n");
					goto err;
				}
				app->add_friend = 1;
				break;

			case 'd':
				if (!parse_pubkey(app->friend_pubkey, optarg, optarg_len))
				{
					fprintf(stderr, "Valid tox address or public key required\n");
					goto err;
				}
				app->del_friend = 1;
				break;

			case 's':
				if (app->client_mode)
				{
					fprintf(stderr, "Client and server modes cannot be used simultaneously\n");
					goto err;
				}

				app->server_mode = 1;
				break;

			case 'c':
				pch = strtok(optarg, ":");
				local_port = atoi(pch);
				if (local_port < 1 || local_port > 65535)
				{
					fprintf(stderr, "The specified local port is not valid\n");
					goto err;
				}

				pch = strtok(NULL, ":");
				if (pch == NULL)
				{
					fprintf(stderr, "The specified friend number is not valid\n");
					goto err;
				}
				friend_number = atoi(pch);

				pch = strtok(NULL, ":");
				remote_port = atoi(pch);
				pch = strtok(NULL, ":");
				if (pch != NULL || remote_port < 1 || remote_port > 65535)
				{
					fprintf(stderr, "The specified remote port is not valid\n");
					goto err;
				}

				if (app->server_mode)
				{
					fprintf(stderr, "Client and server modes cannot be used simultaneously\n");
					goto err;
				}

				ad = (struct acceptor_data*)malloc(sizeof(struct acceptor_data));
				memset(ad, 0, sizeof(struct acceptor_data));
				app->acceptor_list = g_slist_append(app->acceptor_list, ad);
				ad->app = app;
				ad->local_port = local_port;
				ad->remote_port = remote_port;
				ad->friend_number = friend_number;
				ad->conversation_counter = SOURCE_PORT_BEGIN;

				app->client_mode = 1;
				break;

			case 'p':
				app->promiscuous = 1;
				break;

			case 'h':
				app->usage_only = 1;
				print_usage();
				goto out;

			default:
				print_usage();
				goto err;
		}
	}

out:
	return app;

err:
	free(app);
	app = NULL;
	goto out;
}

typedef struct DHT_node {
	const char *ip;
	uint16_t port;
	const char key_hex[TOX_PUBLIC_KEY_SIZE*2 + 1];
	unsigned char key_bin[TOX_PUBLIC_KEY_SIZE];
} DHT_node;

static bool create_tox(struct app_data* app)
{
	Tox_Err_Options_New options_err;
	struct Tox_Options* options = NULL;
	char* savedata = NULL;
	long fsize = 0;
	bool result = FALSE;

	FILE *f = fopen(app->tox_file, "rb");
	if (f)
	{
		if (app->create)
		{
			fprintf(stderr, "File already exists\n");
			fclose(f);
			return FALSE;
		}

		fseek(f, 0, SEEK_END);
		fsize = ftell(f);
		fseek(f, 0, SEEK_SET);

		if (fsize <= 0 || (savedata = (char*)malloc(fsize)) == NULL || fread(savedata, fsize, 1, f) != 1)
		{
			fprintf(stderr, "Invalid tox file\n");
			fclose(f);
			free(savedata);
			return FALSE;
		}

		fclose(f);
	}
	else if (!app->create)
	{
		fprintf(stderr, "Invalid tox file\n");
		return FALSE;
	}

	options = tox_options_new(&options_err);
	if (options == NULL)
	{
		fprintf(stderr, "Unable to create tox options (%d)\n", options_err);
		free(savedata);
		return FALSE;
	}

	if (savedata)
	{
		tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
		tox_options_set_savedata_data(options, (const uint8_t*)savedata, fsize);
	}

	{
		Tox_Err_New new_err;
		app->tox = tox_new(options, &new_err);
		if (app->tox)
		{
			result = TRUE;
		}
		else
		{
			fprintf(stderr, "Unable to create tox instance (%d)\n", new_err);
		}
	}

	tox_options_free(options);
	free(savedata);

	return result;
}

static void update_savedata_file(struct app_data* app)
{
	size_t size = tox_get_savedata_size(app->tox);
	char* savedata = (char*)malloc(size);
	tox_get_savedata(app->tox, (uint8_t*)savedata);

	FILE *f = fopen(app->tox_file, "wb");
	fwrite(savedata, size, 1, f);
	fclose(f);

	free(savedata);
}

static
void bootstrap(Tox *tox)
{
	DHT_node nodes[] =
	{
		{"144.217.167.73", 33445, "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C", {0}},
		{"172.104.215.182", 33445, "DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239", {0}},
		{"188.245.84.166", 33445, "96B66D300BA2B59B98FC42DB1325E7092388F0379593E680ABDBEA03B9C9CE03", {0}},
		{"198.199.98.108", 33445, "BEF0CFB37AF874BD17B9A8F9FE64C75521DB95A37D33C5BDB00E9CF58659C04F", {0}},
		{"tox.initramfs.io", 33445, "3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25", {0}},
		{"node.toxbootstrap.org", 33445, "451C6B9B11DAF61336D8C5892BB00210EEFF3E9C58BE1827BFD442C163155B79", {0}}
	};

	for (size_t i = 0; i < sizeof(nodes)/sizeof(DHT_node); i ++)
	{
		sodium_hex2bin(nodes[i].key_bin, sizeof(nodes[i].key_bin),
					nodes[i].key_hex, sizeof(nodes[i].key_hex)-1, NULL, NULL, NULL);
		tox_bootstrap(tox, nodes[i].ip, nodes[i].port, nodes[i].key_bin, NULL);
		tox_add_tcp_relay(tox, nodes[i].ip, nodes[i].port, nodes[i].key_bin, NULL);
	}
}

static
void print_tox_id(Tox *tox)
{
	uint8_t tox_id_bin[TOX_ADDRESS_SIZE];
	tox_self_get_address(tox, tox_id_bin);

	char tox_id_hex[TOX_ADDRESS_SIZE*2 + 1];
	sodium_bin2hex(tox_id_hex, sizeof(tox_id_hex), tox_id_bin, sizeof(tox_id_bin));

	for (size_t i = 0; i < sizeof(tox_id_hex)-1; i ++)
	{
		tox_id_hex[i] = toupper(tox_id_hex[i]);
	}

	printf("Tox ID: %s\n", tox_id_hex);
}

static
void friend_request_cb(Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length, void *user_data)
{
	tox_friend_add_norequest(tox, public_key, NULL);
}

static void self_connection_status_cb(Tox* tox, TOX_CONNECTION connection_status, void* user_data)
{
	switch (connection_status)
	{
		case TOX_CONNECTION_NONE:
			printf("Offline\n");
			break;
		case TOX_CONNECTION_TCP:
			printf("Online, using TCP\n");
			break;
		case TOX_CONNECTION_UDP:
			printf("Online, using UDP\n");
			break;
	}
}

static void friend_connection_status_cb(Tox* tox, uint32_t friend_number, TOX_CONNECTION connection_status, void* user_data)
{
	switch (connection_status)
	{
		case TOX_CONNECTION_NONE:
			printf("Friend %d:\tOffline\n", friend_number);
			break;
		case TOX_CONNECTION_TCP:
			printf("Friend %d:\tOnline, using TCP\n", friend_number);
			break;
		case TOX_CONNECTION_UDP:
			printf("Friend %d:\tOnline, using UDP\n", friend_number);
			break;
	}
}

bool tox_send_packet(Tox* tox, uint32_t friend_number, const uint8_t* data, size_t length, bool* too_long)
{
	*too_long = FALSE;

	TOX_ERR_FRIEND_CUSTOM_PACKET error;
	if (!tox_friend_send_lossy_packet(tox, friend_number, data, length, &error) || error != TOX_ERR_FRIEND_CUSTOM_PACKET_OK)
	{
		fprintf(stderr, "Write packet failed. Tox send error %d\n", error);
		if (error == TOX_ERR_FRIEND_CUSTOM_PACKET_TOO_LONG)
		{
			*too_long = TRUE;
		}

		return FALSE;
	}

#if 0
	TOX_ERR_FRIEND_SEND_MESSAGE error;
	tox_friend_send_message(tox, friend_number, TOX_MESSAGE_TYPE_NORMAL, data, length, &error);
	if (error != TOX_ERR_FRIEND_SEND_MESSAGE_OK)
	{
		fprintf(stderr, "Write packet failed. Tox send error %d\n", error);
		if (error == TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG)
		{
			*too_long = TRUE;
		}

		return FALSE;
	}
#endif

	return TRUE;
}

static void input_stream_closed(GObject* source_object, GAsyncResult* res, gpointer user_data)
{
	struct connection_data* cd = (struct connection_data*)user_data;
	GError* error = NULL;
	if (!g_input_stream_close_finish((GInputStream*)source_object, res, &error))
	{
		fprintf(stderr, "Input stream close failed: %s\n", error ? error->message : "NULL");
		if (error)
		{
			g_error_free(error);
		}
		if (cd->pseudotcp_socket)
		{
			pseudo_tcp_socket_close(cd->pseudotcp_socket, TRUE);
		}
		return;
	}

	printf("Input stream closed\n");
}

static void output_stream_closed(GObject* source_object, GAsyncResult* res, gpointer user_data)
{
	struct connection_data* cd = (struct connection_data*)user_data;
	GError* error = NULL;
	if (!g_output_stream_close_finish((GOutputStream*)source_object, res, &error))
	{
		fprintf(stderr, "Output stream close failed: %s\n", error ? error->message : "NULL");
		if (error)
		{
			g_error_free(error);
		}
		if (cd->pseudotcp_socket)
		{
			pseudo_tcp_socket_close(cd->pseudotcp_socket, TRUE);
		}
		return;
	}

	error = NULL;
	if (!g_socket_shutdown(g_socket_connection_get_socket(cd->socket_connection), FALSE, TRUE, &error))
	{
		fprintf(stderr, "Socket shutdown failed: %s\n", error ? error->message : "NULL");
		if (error)
		{
			g_error_free(error);
		}
		if (cd->pseudotcp_socket)
		{
			pseudo_tcp_socket_close(cd->pseudotcp_socket, TRUE);
		}
		return;
	}

	printf("Output stream closed\n");
}

static void io_stream_closed(GObject* source_object, GAsyncResult* res, gpointer user_data)
{
	struct connection_data* cd = (struct connection_data*)user_data;
	GError* error = NULL;
	if (!g_io_stream_close_finish((GIOStream*)source_object, res, &error))
	{
		fprintf(stderr, "IO stream close failed: %s\n", error ? error->message : "NULL");
		if (error)
		{
			g_error_free(error);
		}

		goto out;
	}

	printf("IO stream closed\n");

out:
	g_object_unref(cd->socket_connection);
	cd->socket_connection = NULL;

	free_connection_data(cd);
}

static void input_stream_read(GObject* source_object, GAsyncResult* res, gpointer user_data)
{
	struct connection_data* cd = (struct connection_data*)user_data;
	GError* error = NULL;
	gssize len = g_input_stream_read_finish((GInputStream*)source_object, res, &error);
	if (len > 0)
	{
		printf("Input stream read %d\n", len);
		cd->tcp2tox_end = len;
		cd->tcp2tox_stat += len;

		//TODO: pseudo_tcp_socket_can_send(cd->pseudotcp_socket);
		cd->pseudotcp_callbacks.PseudoTcpWritable(cd->pseudotcp_socket, cd);
	}
	else if (!len)
	{
		printf("Input stream remotely closed\n");
		//TODO: pseudo_tcp_socket_shutdown(cd->pseudotcp_socket, PSEUDO_TCP_SHUTDOWN_WR);
		g_input_stream_close_async(g_io_stream_get_input_stream((GIOStream*)cd->socket_connection), G_PRIORITY_DEFAULT, NULL, input_stream_closed, cd);
		if (cd->pseudotcp_socket)
		{
			pseudo_tcp_socket_close(cd->pseudotcp_socket, FALSE);
		}
	}
	else
	{
		fprintf(stderr, "Input stream read failed: %s\n", error ? error->message : "NULL");
		if (error)
		{
			g_error_free(error);
		}
		if (cd->pseudotcp_socket)
		{
			pseudo_tcp_socket_close(cd->pseudotcp_socket, TRUE);
		}
	}
}

static void output_stream_written(GObject* source_object, GAsyncResult* res, gpointer user_data)
{
	struct connection_data* cd = (struct connection_data*)user_data;
	GError* error = NULL;
	gsize bytes_written;
	if (!g_output_stream_write_all_finish((GOutputStream*)source_object, res, &bytes_written, &error))
	{
		fprintf(stderr, "Output stream write failed: %s\n", error ? error->message : "NULL");
		if (error)
		{
			g_error_free(error);
		}
		if (cd->pseudotcp_socket)
		{
			pseudo_tcp_socket_close(cd->pseudotcp_socket, TRUE);
		}
		return;
	}

	printf("Output stream written %d\n", bytes_written);

	cd->tox2tcp_begin = cd->tox2tcp_end = 0;
	cd->pseudotcp_callbacks.PseudoTcpReadable(cd->pseudotcp_socket, cd);
}

static void opened(PseudoTcpSocket *sock, gpointer data)
{
	printf("Pseudotcp opened\n");
	struct connection_data* cd = (struct connection_data*)data;

	if (cd->app->server_mode)
	{
		GSocketClient* client = g_socket_client_new();
		g_socket_client_connect_async(client, g_network_address_new_loopback(cd->conversation & 0xFFFF), NULL, outgoing_connected, cd);
		return;
	}

	g_input_stream_read_async(g_io_stream_get_input_stream((GIOStream*)cd->socket_connection), cd->tcp2tox_buf, sizeof(cd->tcp2tox_buf), G_PRIORITY_DEFAULT, NULL, input_stream_read, cd);
}

static void readable(PseudoTcpSocket *sock, gpointer data)
{
	printf("Pseudotcp readable\n");
	struct connection_data* cd = (struct connection_data*)data;

	if (!cd->socket_connection ||
	    g_output_stream_is_closing(g_io_stream_get_output_stream((GIOStream*)cd->socket_connection)) ||
	    g_output_stream_is_closed(g_io_stream_get_output_stream((GIOStream*)cd->socket_connection)) ||
	    !cd->pseudotcp_socket)
	{
		return;
	}

	if (cd->tox2tcp_begin != cd->tox2tcp_end)
	{
		return;
	}

	gint len = pseudo_tcp_socket_recv(sock, cd->tox2tcp_buf, sizeof(cd->tox2tcp_buf));
	if (len > 0)
	{
		printf("Pseudotcp read %d\n", len);
		cd->tox2tcp_end = len;
		cd->tox2tcp_stat += len;
		g_output_stream_write_all_async(g_io_stream_get_output_stream((GIOStream*)cd->socket_connection), cd->tox2tcp_buf, cd->tox2tcp_end, G_PRIORITY_DEFAULT, NULL, output_stream_written, cd);
	}
	else if (!len)
	{
		printf("Pseudotcp remotely closed\n");
		g_output_stream_close_async(g_io_stream_get_output_stream((GIOStream*)cd->socket_connection), G_PRIORITY_DEFAULT, NULL, output_stream_closed, cd);
	}
	else if (pseudo_tcp_socket_get_error(sock) != EWOULDBLOCK)
	{
		fprintf(stderr, "Pseudotcp read failed with error %d\n", pseudo_tcp_socket_get_error(sock));
		pseudo_tcp_socket_close(cd->pseudotcp_socket, TRUE);
	}
	else
	{
		printf("Pseudotcp read would block\n");
	}
}

static void writable(PseudoTcpSocket *sock, gpointer data)
{
	printf("Pseudotcp writable\n");
	struct connection_data* cd = (struct connection_data*)data;

	if (!cd->pseudotcp_socket)
	{
		return;
	}

	if (cd->tcp2tox_begin == cd->tcp2tox_end)
	{
		return;
	}

	gint wlen = pseudo_tcp_socket_send(sock, cd->tcp2tox_buf + cd->tcp2tox_begin, cd->tcp2tox_end - cd->tcp2tox_begin);
	adjust_clock(cd);
	if (wlen >= 0)
	{
		printf("Pseudotcp sent %d\n", wlen);
		cd->tcp2tox_begin += wlen;
	}
	else if (pseudo_tcp_socket_get_error(sock) != EWOULDBLOCK)
	{
		fprintf(stderr, "Pseudotcp read failed with error %d\n", pseudo_tcp_socket_get_error(sock));
		pseudo_tcp_socket_close(cd->pseudotcp_socket, TRUE);
		return;
	}
	else
	{
		printf("Pseudotcp write would block\n");
	}

	if (cd->tcp2tox_begin == cd->tcp2tox_end)
	{
		cd->tcp2tox_begin = cd->tcp2tox_end = 0;
		g_input_stream_read_async(g_io_stream_get_input_stream((GIOStream*)cd->socket_connection), cd->tcp2tox_buf, sizeof(cd->tcp2tox_buf), G_PRIORITY_DEFAULT, NULL, input_stream_read, cd);
	} 
}

static void closed(PseudoTcpSocket *sock, guint32 err, gpointer data)
{
	fprintf(stderr, "Pseudotcp closed with error %d\n", err);
	struct connection_data* cd = (struct connection_data*)data;
}

static PseudoTcpWriteResult write_packet(PseudoTcpSocket* sock, const gchar* buffer, guint32 len, gpointer data)
{
	printf("Write packet %d\n", len);
	for (uint32_t i = 0; i != len && i != 16; ++i)
	{
		printf(" %02X", buffer[i] & 0xff);
	}
	printf("\n");

	struct connection_data* cd = (struct connection_data*)data;
	cd->app->last_tox_activity_time = g_get_monotonic_time();

	bool too_long = FALSE;
	if (tox_send_packet(cd->app->tox, cd->friend_number, buffer, len, &too_long))
	{
		return WR_SUCCESS;
	}

	return too_long ? WR_TOO_LARGE : WR_FAIL;
}

static struct connection_data* create_connection_data(struct app_data* app, uint32_t friend_number, uint32_t conversation)
{
	struct connection_data* cd = (struct connection_data*)malloc(sizeof(struct connection_data));
	memset(cd, 0, sizeof(struct connection_data));
	app->connection_list = g_slist_append(app->connection_list, cd);
	cd->app = app;
	cd->pseudotcp_callbacks.user_data = cd;
	cd->pseudotcp_callbacks.PseudoTcpOpened = opened;
	cd->pseudotcp_callbacks.PseudoTcpReadable = readable;
	cd->pseudotcp_callbacks.PseudoTcpWritable = writable;
	cd->pseudotcp_callbacks.PseudoTcpClosed = closed;
	cd->pseudotcp_callbacks.WritePacket = write_packet;
	cd->pseudotcp_socket = pseudo_tcp_socket_new(conversation, &cd->pseudotcp_callbacks);
	cd->friend_number = friend_number;
	cd->conversation = conversation;
	pseudo_tcp_socket_notify_mtu(cd->pseudotcp_socket, app->mtu);
	return cd;
}

static gboolean delayed_free_connection_data(gpointer user_data)
{
	struct connection_data* cd = (struct connection_data*)user_data;

	printf("Removed connection data %8X\n", cd->conversation);

	cd->app->connection_list = g_slist_remove(cd->app->connection_list, cd);
	free(cd);

	return FALSE;
}

static void free_connection_data(struct connection_data* cd)
{
	printf("Removing connection data %8X\n", cd->conversation);
	g_timeout_add(TIME_WAIT_INTERVAL, delayed_free_connection_data, cd);
}

static gboolean notify_clock(gpointer user_data)
{
	struct connection_data* cd = (struct connection_data*)user_data;
	//printf("tcp2tox_stat = %d\n", cd->tcp2tox_stat);
	//printf("tox2tcp_stat = %d\n", cd->tox2tcp_stat);
	pseudo_tcp_socket_notify_clock(cd->pseudotcp_socket);
	adjust_clock(cd);
	return FALSE;
}

static void adjust_clock(struct connection_data* cd)
{
	guint64 timeout = 0;

	if (cd->pseudotcp_clock != 0)
	{
		g_source_remove(cd->pseudotcp_clock);
		cd->pseudotcp_clock = 0;
	}

	if (pseudo_tcp_socket_get_next_clock(cd->pseudotcp_socket, &timeout))
	{
		timeout -= g_get_monotonic_time () / 1000;
		cd->pseudotcp_clock = g_timeout_add(timeout, notify_clock, cd);
	}
	else
	{
		g_object_unref(cd->pseudotcp_socket);
		cd->pseudotcp_socket = NULL;

		printf("Pseudotcp closed\n");
		if (cd->socket_connection)
		{
			g_io_stream_close_async((GIOStream*)cd->socket_connection, G_PRIORITY_DEFAULT, NULL, io_stream_closed, cd);
		}
		else
		{
			free_connection_data(cd);
		}
	}
}

static void outgoing_connected(GObject* source_object, GAsyncResult* res, gpointer user_data)
{
	printf("Connected to service\n");
	struct connection_data* cd = (struct connection_data*)user_data;
	GSocketClient* client = (GSocketClient*)source_object;
	GError* error = NULL;
	GSocketConnection* connection = g_socket_client_connect_finish(client, res, &error);
	if (!connection)
	{
		fprintf(stderr, "Connection to service failed: %s\n", error ? error->message : "NULL");
		if (error)
		{
			g_error_free(error);
		}
		if (cd->pseudotcp_socket)
		{
			pseudo_tcp_socket_close(cd->pseudotcp_socket, TRUE);
		}
		return;
	}

	//TODO: g_tcp_connection_set_graceful_disconnect((GTcpConnection*)connection, TRUE);
	cd->socket_connection = connection;

	g_input_stream_read_async(g_io_stream_get_input_stream((GIOStream*)cd->socket_connection), cd->tcp2tox_buf, sizeof(cd->tcp2tox_buf), G_PRIORITY_DEFAULT, NULL, input_stream_read, cd);
	cd->pseudotcp_callbacks.PseudoTcpReadable(cd->pseudotcp_socket, cd);
	return;

	pseudo_tcp_socket_connect(cd->pseudotcp_socket);
	adjust_clock(cd);
}
 
static void incoming_tox_data(uint32_t friend_number, const uint8_t* data, size_t length, struct app_data* app)
{
	app->last_tox_activity_time = g_get_monotonic_time();

	uint32_t conversation = ntohl(((uint32_t*)data)[0]);

	if (conversation == CONVERSATION_NUM_CMD)
	{
		if (app->server_mode)
		{
			uint32_t new_conversation = ntohl(((uint32_t*)data)[1]);
			printf("Connection request received %8X\n", new_conversation);
			GSocketClient* client = g_socket_client_new();

			struct connection_data* cd = create_connection_data(app, friend_number, new_conversation);

			g_socket_client_connect_async(client, g_network_address_new_loopback(new_conversation & 0xFFFF), NULL, outgoing_connected, cd);
		}

		return;
	}

	printf("Data for conversation %8X received\n", conversation);

	struct connection_data* cd = NULL;

	GSList* list = app->connection_list;
	while (list)
	{
		cd = (struct connection_data*)list->data;
		if (cd->friend_number == friend_number && cd->conversation == conversation)
		{
			if (cd->pseudotcp_socket)
			{
				pseudo_tcp_socket_notify_packet(cd->pseudotcp_socket, (const gchar*)data, length);
				adjust_clock(cd);

				cd->pseudotcp_callbacks.PseudoTcpReadable(cd->pseudotcp_socket, cd);
			}
			break;
		}

		list = g_slist_next(list);
	}

	if (!list)
	{
		if (app->server_mode)
		{
			printf("Connection request received %8X\n", conversation);

			struct connection_data* cd = create_connection_data(app, friend_number, conversation);
			pseudo_tcp_socket_notify_packet(cd->pseudotcp_socket, (const gchar*)data, length);
			adjust_clock(cd);
		}
	}
}

static void friend_message_cb(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type, const uint8_t *message, size_t length, void *user_data)
{
	printf("Got a %d tox message from %d, %d bytes\n", type, friend_number, length);
	struct app_data* app = (struct app_data*)user_data;
	incoming_tox_data(friend_number, message, length, app);
}

static void friend_lossy_packet_cb(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length, void *user_data)
{
	printf("Got lossy tox data from %d, %d bytes\n", friend_number, length);
	struct app_data* app = (struct app_data*)user_data;
	incoming_tox_data(friend_number, data, length, app);
}

static void friend_lossless_packet_cb(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length, void *user_data)
{
	printf("Got lossless tox data from %d, %d bytes\n", friend_number, length);
	struct app_data* app = (struct app_data*)user_data;
	incoming_tox_data(friend_number, data, length, app);
}

static gboolean notify_tox_clock(gpointer user_data)
{
	struct app_data* app = (struct app_data*)user_data;
	tox_iterate(app->tox, app);

	uint32_t interval;
	if (g_get_monotonic_time() - app->last_tox_activity_time > STANDBY_TIMEOUT)
	{
		interval = tox_iteration_interval(app->tox);
	}
	else
	{
		interval = 1;
	}

	if (interval != app->tox_iterate_interval)
	{
		g_timeout_add(interval, notify_tox_clock, app);
		app->tox_iterate_interval = interval;
		return FALSE;
	}

	return TRUE;
}

static gboolean incoming_connected(GSocketService* service, GSocketConnection* connection, GObject* source_object, gpointer user_data)
{
	struct acceptor_data* ad = (struct acceptor_data*)user_data;

	if (tox_self_get_connection_status(ad->app->tox) == TOX_CONNECTION_NONE)
	{
		return TRUE;
	}

	TOX_ERR_FRIEND_QUERY error;
	if (tox_friend_get_connection_status(ad->app->tox, ad->friend_number, &error) == TOX_CONNECTION_NONE || error != TOX_ERR_FRIEND_QUERY_OK)
	{
		return TRUE;
	}

	g_object_ref(connection);

	uint32_t new_conversation = ad->conversation_counter++;
	new_conversation = (new_conversation << 16) | ad->remote_port;
	printf("Requesting connection %8X\n", new_conversation);

	struct connection_data* cd = create_connection_data(ad->app, ad->friend_number, new_conversation);

	cd->socket_connection = connection;
	//TODO: g_tcp_connection_set_graceful_disconnect((GTcpConnection*)connection, TRUE);

	pseudo_tcp_socket_connect(cd->pseudotcp_socket);

	adjust_clock(cd);
	return FALSE;

	uint8_t data[256];
	((uint32_t*)data)[0] = htonl(CONVERSATION_NUM_CMD);
	((uint32_t*)data)[1] = htonl(new_conversation);
	printf("Requesting connection %8X\n", new_conversation);

	ad->app->last_tox_activity_time = g_get_monotonic_time();

	bool too_long = FALSE;
	return tox_send_packet(cd->app->tox, cd->friend_number, data, sizeof(data), &too_long) == FALSE;
}

int main(int argc, char* argv[])
{
	int res = 0;
	GSocketService* listener = NULL;
	uint32_t* friend_list = NULL;

	struct app_data* app = create_app_data(argc, argv);
	if (!app)
	{
		goto err;
	}

	if (app->usage_only)
	{
		print_usage();
		goto out;
	}

	if (app->tox_file[0] == 0)
	{
		print_usage();
		goto err;
	}

	if (!create_tox(app))
	{
		goto err;
	}

	if (app->add_friend)
	{
		tox_friend_add_norequest(app->tox, app->friend_pubkey, NULL);
	}

	if (app->del_friend)
	{
		TOX_ERR_FRIEND_BY_PUBLIC_KEY error;
		uint32_t friend_number = tox_friend_by_public_key(app->tox, app->friend_pubkey, &error);
		if (friend_number == ULONG_MAX)
		{
			fprintf(stderr, "No friend with the specified public key found\n");
			goto err;
		}

		tox_friend_delete(app->tox, friend_number, NULL);
	}

	print_tox_id(app->tox);

	size_t size = tox_self_get_friend_list_size(app->tox);
	if (size)
	{
		friend_list = (uint32_t*)malloc(size * sizeof(uint32_t));
		tox_self_get_friend_list(app->tox, friend_list);

		printf("Friend list:\n");
	}

	for (uint32_t* friend_ptr = friend_list; friend_ptr != friend_list + size; ++friend_ptr)
	{
		uint8_t public_key[TOX_PUBLIC_KEY_SIZE];
		TOX_ERR_FRIEND_GET_PUBLIC_KEY error;
		if (tox_friend_get_public_key(app->tox, *friend_ptr, public_key, &error))
		{
			char public_key_hex[TOX_PUBLIC_KEY_SIZE * 2 + 1];
			sodium_bin2hex(public_key_hex, sizeof(public_key_hex), public_key, sizeof(public_key));

			for (size_t i = 0; i < sizeof(public_key_hex)-1; i ++) {
				public_key_hex[i] = toupper(public_key_hex[i]);
			}

			printf("	%d:\t%s\n", *friend_ptr, public_key_hex);
		}
	}

	if (app->create || app->add_friend || app->del_friend)
	{
		update_savedata_file(app);
		goto out;
	}

	if (!app->client_mode && !app->server_mode)
	{
		goto out;
	}

	const char *name = app->server_mode ? "Server mode" : "Client mode";
	tox_self_set_name(app->tox, (const uint8_t*)name, strlen(name), NULL);

	const char *status_message = app->server_mode ? "Waiting for requests to establish connections" : "Will send request to establish connections";
	tox_self_set_status_message(app->tox, (const uint8_t*)status_message, strlen(status_message), NULL);

	bootstrap(app->tox);

	if (app->promiscuous)
	{
		tox_callback_friend_request(app->tox, friend_request_cb);
	}

	tox_callback_friend_message(app->tox, friend_message_cb);
	tox_callback_friend_lossy_packet(app->tox, friend_lossy_packet_cb);
	tox_callback_friend_lossless_packet(app->tox, friend_lossless_packet_cb);
	tox_callback_self_connection_status(app->tox, self_connection_status_cb);
	tox_callback_friend_connection_status(app->tox, friend_connection_status_cb);

	setlocale (LC_ALL, "en-US");

	mainloop = g_main_loop_new(NULL, FALSE);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	if (app->client_mode)
	{
		listener = g_socket_service_new();

		GSList* list = app->acceptor_list;
		while (list)
		{
			struct acceptor_data* ad = (struct acceptor_data*)list->data;

			bool friend_number_found = FALSE;
			for (uint32_t* friend_ptr = friend_list; friend_ptr != friend_list + size; ++friend_ptr)
			{
				if (ad->friend_number == *friend_ptr)
				{
					friend_number_found = TRUE;
				}
			}

			if (!friend_number_found)
			{
				fprintf(stderr, "Friend with number %d not found", ad->friend_number);
				goto err;
			}

			GInetAddress* loopback_ipv4_address = g_inet_address_new_loopback(G_SOCKET_FAMILY_IPV4);
			GSocketAddress* ipv4_socket_address = g_inet_socket_address_new(loopback_ipv4_address, ad->local_port);
			g_object_unref(loopback_ipv4_address);
			g_socket_listener_add_address((GSocketListener*)listener, ipv4_socket_address, G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP, NULL, NULL, NULL);
			g_object_unref(ipv4_socket_address);

			GInetAddress* loopback_ipv6_address = g_inet_address_new_loopback(G_SOCKET_FAMILY_IPV6);
			GSocketAddress* ipv6_socket_address = g_inet_socket_address_new(loopback_ipv6_address, ad->local_port);
			g_object_unref(loopback_ipv6_address);
			g_socket_listener_add_address((GSocketListener*)listener, ipv6_socket_address, G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP, NULL, NULL, NULL);
			g_object_unref(ipv6_socket_address);

			g_signal_connect(listener, "incoming", G_CALLBACK(incoming_connected), ad);

			list = g_slist_next(list);
		}

		g_socket_service_start(listener);
	}

	notify_tox_clock(app);

	g_main_loop_run(mainloop);

	printf("Quitting...\n");

out:
	if (listener)
	{
		g_socket_service_stop(listener);
		g_object_unref(listener);
	}

	if (app->tox)
	{
		tox_kill(app->tox);
	}

	GSList* list = app->acceptor_list;
	while (list)
	{
		free(list->data);
		list = g_slist_delete_link(list, list);
	}

	free(friend_list);
	free(app);

out2:
	return res;

err:
	res = -1;

	if (!app)
	{
		goto out2;
	}

	goto out;
}
