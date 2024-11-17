/*
"no dependancy" websocket rtsp proxy

each client should create 2 enpoints. one for control. the other for data.
the control endpoint must be initialized
the data enpoint must be joined to the control endpoint

The control endpoint can then be used to pass rtsp request to the rtsp server
The rtsp responses will be delivered to the control endpoint
Interleaved rtsp data will be passed to the data endpoint

This implementation is single threaded and probably won't perform incredibly well with many clients.
Since there is no encoding or buffering performed I don't imagine this to be an issue with a moderate number of concurent clients.

*/

#include <arpa/inet.h> // inet_addr()
#include <sys/time.h> // timeval
#include <assert.h>
#include <ctype.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void _dbg(int line, char *fmt, ...) {
    fprintf(stderr, "% 4d] ", line);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

#define DBG(...) _dbg(__LINE__, __VA_ARGS__)

static void dump(const char *prefix, const void *const buf, int len) {
    fprintf(stderr, "(%d bytes) %s", len, prefix);
    for (int i = 0; i < len; i++) {
        int c = ((uint8_t *)buf)[i];
        if (c == ' ') {
            fprintf(stderr, " ");
        } else if (c == '\r') {
            fprintf(stderr, "\\r");
        } else if (c == '\n') {
            fprintf(stderr, "\\n");
        } else if (c == '\t') {
            fprintf(stderr, "\\t");
        } else if (c == '\v') {
            fprintf(stderr, "\\x%02x", c);
        } else if (isprint(c)) {
            fprintf(stderr, "%c", c);
        } else {
            fprintf(stderr, "\\x%02x", c);
        }
    }
    fprintf(stderr, "\n");
}

#include <sha1.h>
#include <cencode.h>

// base64 encode some data. destination must be large enough...
static uint8_t *b64_enc(uint8_t *dst, int dstlen, uint8_t *src, size_t len) {
    base64_encodestate s;

    base64_init_encodestate(&s);
    char *c = (char *)dst;
    c += base64_encode_block((char *)src, len, c, &s);
    c += base64_encode_blockend(c, &s);
    c -= 1; // remove terminating \n
    *c = 0;
    return (uint8_t *)c;
}

// find a propery in a message and interpret it as u16
int find_prop(const uint8_t *msg, const char *name, uint16_t *val) {
    const unsigned char *headerend = (const unsigned char *)strstr((char *)msg, "\r\n\r\n");
    if (!headerend) {
        return -1;
    }

    const int header_len = headerend - msg;
    const unsigned char *prop = (const unsigned char *)strstr((char *)msg, name);
    if (!prop) {
        return -1;
    }

    if (msg + header_len < prop) {
        return -1;
    }

    const unsigned char *strval = prop + strlen(name);
    while (*strval == ' ')
        strval++;

    *val = atoi((const char *)strval);
    return 0;
}

#define WS_HS_ACCEPT "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
#define WS_FIN 0x80
#define WS_FR_OP_CONT 0x00
#define WS_FR_OP_TXT 0x01
#define WS_FR_OP_BIN 0x02
#define WS_FR_OP_CLOSE 0x08
#define WS_FR_OP_PING 0x09
#define WS_FR_OP_PONG 0x0A
#define WS_KEY_LEN 24
#define WS_MAGIC_STRING "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_MAGIC_STRING_LEN 36

#define STATE_UNINITIALIZED 0
#define STATE_INITIALIZED 1
#define STATE_JOINED 2

typedef struct {
    int cfd;    // ws client sock
    int rtsp;   // rtsp sock (if initialized)
    int dataep; // ws dataep (if joined)

    // websock data area for incoming requests and upgrade negotiation
    uint8_t *ws_buf;
    int ws_pos;

    // is this client upgraded yet?
    int isupgraded;

    // websocket data area for agregated frames
    uint8_t *ag_buf;
    int ag_pos;

    // rtsp data area for incoming data
    uint8_t *rtsp_buf;
    int rtsp_pos;

    int state;

    // wps sequence counter
    int seq;
} client_t;

#define MAXCLIENTS 512
#define WS_BUF_SIZE 1024
#define AG_BUF_SIZE 1024 * 8
#define RTSP_BUF_SIZE 1024 * 8
#define MAX_HEAD_LEN 256

static client_t gclient[MAXCLIENTS];

static int prefix_match(const char *head, const unsigned char *msg, int msglen) {
    int hlen = strlen(head);
    if (msglen < hlen)
        return -1;

    return memcmp(head, msg, hlen);
}

static const char *getenv_dflt(const char *name, const char *deflt) {
    const char *val = getenv(name);
    if (!val) {
        val = deflt;
    }
    return val;
}

static int ws_bind_socket(const char *host, const char *port) {
    int reuse = 1;
    int sock = -1;
    struct addrinfo hints;
    struct addrinfo *results;

    // Prepare the getaddrinfo structure.
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &results) != 0) {
        DBG("getaddrinfo() failed");
        return -1;
    }

    // Try to create a socket with one of the returned addresses.
    for (struct addrinfo *try = results; try != NULL; try = try->ai_next) {
        // try to make a socket with this setup
        sock = socket(try->ai_family, try->ai_socktype, try->ai_protocol);
        if (sock < 0) {
            continue;
        }

        // Reuse previous address.
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse)) < 0) {
            DBG("setsockopt(SO_REUSEADDR) failed");
            freeaddrinfo(results);
            return -1;
        }

        // Bind.
        if (bind(sock, try->ai_addr, try->ai_addrlen) < 0) {
            DBG("Bind failed");
            freeaddrinfo(results);
            return -1;
        }

        // if it worked, we're done.
        break;
    }

    freeaddrinfo(results);

    /* Check if binded with success. */
    if (sock < 0) {
        DBG("couldn't find a port to bind to");
    }

    return sock;
}

static void ws_sendheader(int cfd, uint64_t size, uint8_t type) {
    uint8_t frame[128];
    frame[0] = (WS_FIN | type);

    int hlen;
    if (size <= 125) {
        // Split the size between octets.
        frame[1] = size & 0x7F;
        hlen = 2;
    } else if (size >= 126 && size <= 65535) {
        // Size between 126 and 65535 bytes.
        frame[1] = 126;
        frame[2] = (size >> 8) & 0xff;
        frame[3] = size & 0xff;
        hlen = 4;
    } else {
        // More than 65535 bytes.
        frame[1] = 127;
        frame[2] = (unsigned char)((size >> 56) & 0xff);
        frame[3] = (unsigned char)((size >> 48) & 0xff);
        frame[4] = (unsigned char)((size >> 40) & 0xff);
        frame[5] = (unsigned char)((size >> 32) & 0xff);
        frame[6] = (unsigned char)((size >> 24) & 0xff);
        frame[7] = (unsigned char)((size >> 16) & 0xff);
        frame[8] = (unsigned char)((size >> 8) & 0xff);
        frame[9] = (unsigned char)(size & 0xff);
        hlen = 10;
    }
    write(cfd, frame, hlen);
}

static void ws_sendbody(int cfd, uint8_t *body, uint64_t bodysize) {
    write(cfd, body, bodysize);
}

static void ws_sendframe(int cfd, uint8_t *pkt, uint64_t size, uint8_t type) {
    ws_sendheader(cfd, size, type);
    ws_sendbody(cfd, pkt, size);
}

static void wsp_send_simple(int cfd, uint16_t code, const char *msg) {
    char pkt[128];
    int len = sprintf(pkt, "WSP/1.1 %d %s\r\n\r\n", code, msg);
    dump("WSP << ", pkt, len);
    ws_sendframe(cfd, (uint8_t *)pkt, len, WS_FR_OP_TXT);
}

static void wsp_send_simple_cs(int cfd, uint16_t code, const char *msg, uint16_t channelid, uint16_t seq) {
    char pkt[128];
    int len = sprintf(pkt, "WSP/1.1 %d %s\r\nchannel: %d\r\nseq: %d\r\n\r\n", code, msg, channelid, seq);
    dump("WSP << ", pkt, len);
    ws_sendframe(cfd, (uint8_t *)pkt, len, WS_FR_OP_TXT);
}

static int rtsp_connect(const char *host, const char *port) {
    int sock = -1;
    struct addrinfo hints;
    struct addrinfo *results;

    // Prepare the getaddrinfo structure.
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &results) != 0) {
        DBG("getaddrinfo() failed");
        return -1;
    }

    // Try to create a socket with one of the returned addresses.
    for (struct addrinfo *try = results; try != NULL; try = try->ai_next) {
        // try to make a socket with this setup
        sock = socket(try->ai_family, try->ai_socktype, try->ai_protocol);
        if (sock < 0) {
            continue;
        }

        //addr.sin_port = htons(port);
        if (connect(sock, try->ai_addr, try->ai_addrlen) != 0) {
            DBG("RTSP CONNECT FAILED");
            freeaddrinfo(results);
            close(sock);
            return -1;
        } else {
            DBG("RTSP CONNECT OK");
        }
        break;
    }

    freeaddrinfo(results);

    return sock;
}

static int rtsp_send(int rtsp, const unsigned char *msg, uint64_t size) {
    while (size) {
        ssize_t ret = write(rtsp, msg, size);
        if (ret <= 0) {
            return -1;
        }
        msg += ret;
        size -= ret;
    }

    return 0;
}

static int rtsp_init_channel(client_t *client, uint8_t *host, uint8_t *port) {
    client->rtsp_buf = malloc(RTSP_BUF_SIZE + 1);
    if (!client->rtsp_buf) {
        perror("malloc");
        return -1;
    }

    client->rtsp = rtsp_connect((char *)host, (char *)port);
    if (client->rtsp < 0) {
        return -1;
    }

    client->state = STATE_INITIALIZED;
    return 0;
}

static uint8_t *get_header_option(const char *key, uint8_t *buf) {
    uint8_t *str = (uint8_t *)strstr((char *)buf, (char *)key);
    if (!str)
        return NULL;
    str += strlen((char *)key);
    while (*str == ' ')
        str++;
    return str;
}

static void terminate_option(uint8_t *val) {
    while (*val != '\r' && *val != '\r' && *val != '\0')
        val++;
    *val = '\0';
}

static int on_connect(client_t *client, int cfd) {
    assert(!client->ws_buf);
    assert(!client->ag_buf);
    assert(!client->rtsp_buf);

    client->ws_buf = malloc(WS_BUF_SIZE + 1);
    if (!client->ws_buf) {
        perror("malloc");
        return -1;
    }
    client->ws_buf[WS_BUF_SIZE] = 0;

    client->ag_buf = malloc(AG_BUF_SIZE + 1);
    if (!client->ag_buf) {
        perror("malloc");
        free(client->ws_buf);
        return -1;
    }

    client->cfd = cfd;

    return 0;
}

static void on_close(client_t *client) {
    if (client->ws_buf) free(client->ws_buf);
    if (client->ag_buf) free(client->ag_buf);
    if (client->rtsp_buf) free(client->rtsp_buf);
    if (client->cfd > 0) {
        close(client->cfd);
    }
    if (client->rtsp > 0) {
        close(client->rtsp);
    }
    memset(client, 0, sizeof(*client));
}

// there is websocket data available
static int on_message(client_t *client, uint8_t *msg, int size) {
    assert(msg[size] == '\0');
    dump("WSP >> ", msg, size);
    const unsigned char *headerend = (const unsigned char *)strstr((char *)msg, "\r\n\r\n");
    if (!headerend) {
        wsp_send_simple(client->cfd, 400, "oops");
        DBG("NO HEADER");
        return -1;
    }
    const int header_len = headerend - msg;
    const int data_offset = header_len + 4;

    uint16_t seq = 0;
    uint16_t channelid = 0;
    uint16_t clen = 0;
    find_prop(msg, "seq:", &seq);
    find_prop(msg, "channel:", &channelid);
    find_prop(msg, "contentLength:", &clen);
    uint8_t *host = get_header_option("host:", msg);
    uint8_t *port = get_header_option("port:", msg);

    if (prefix_match("WSP/1.1 INIT\r\n", msg, size) == 0) {
        if (!(host&&port)) {
            wsp_send_simple(client->cfd, 400, "oops");
            DBG("CLIENT MUST SUPPLY HOST AND PORT");
            return -1;
        }
        terminate_option(host);
        terminate_option(port);
        if (client->state != STATE_UNINITIALIZED) {
            wsp_send_simple(client->cfd, 400, "oops 8");
            DBG("WSP ALREADY INITIALIZED");
            return -1;
        }

        int err = rtsp_init_channel(client, host, port);
        if (err) {
            wsp_send_simple(client->cfd, 400, "oops 9");
            DBG("WSP UNABLE TO INITIALIZE CHANNEL");
            return -1;
        }

        int idx = (client - gclient);
        wsp_send_simple_cs(client->cfd, 200, "OK", idx + 1, seq);
        return 0;
    } else if (prefix_match("WSP/1.1 JOIN\r\n", msg, size) == 0) {
        if (client->state != STATE_UNINITIALIZED) {
            wsp_send_simple(client->cfd, 400, "oops 1");
            DBG("WSP ALREADY JOINED");
            return -1;
        }

        // find the ctrl endpoint and transfer this data endpoint to it
        int idx = channelid - 1;
        if (idx < 0 || idx >= MAXCLIENTS) {
            wsp_send_simple(client->cfd, 400, "oops 2");
            DBG("WSP bad channel id");
            return -1;
        }

        client_t *joinee = &gclient[idx];
        if (joinee->cfd <= 0) {
            wsp_send_simple(client->cfd, 400, "oops 3");
            DBG("WSP joinee has no control channel");
            return -1;
        }
        if (joinee->dataep > 0) {
            wsp_send_simple(client->cfd, 400, "oops 4");
            DBG("WSP joinee already has data channel");
            return -1;
        }

        joinee->dataep = client->cfd;

        wsp_send_simple_cs(client->cfd, 200, "OK", channelid, seq);
        client->state = STATE_JOINED;

        return 0;
    } else if (prefix_match("WSP/1.1 WRAP\r\n", msg, size) == 0) {
        if (client->state != STATE_INITIALIZED) {
            wsp_send_simple(client->cfd, 400, "oops 5");
            DBG("WSP NOT INITIALIZED");
            return -1;
        }

        if (client->rtsp <= 0) {
            wsp_send_simple(client->cfd, 400, "oops 6");
            DBG("WSP no rtsp client socket to WRAP to");
            return -1;
        }

        client->seq = seq;

        rtsp_send(client->rtsp, &msg[data_offset], size - data_offset);
        return 0;
    } else {
        wsp_send_simple(client->cfd, 400, "oops 7");
        DBG("WSP UNKNOWN COMMAND");
        return -1;
    }
}

// there is rtsp data available
static int on_rtsp_data(client_t *client) {
    if (client->rtsp_pos >= RTSP_BUF_SIZE) {
        DBG("RTSP data overflow");
        on_close(client);
        return -1;
    }

    ssize_t ret = read(client->rtsp, client->rtsp_buf + client->rtsp_pos, RTSP_BUF_SIZE - client->rtsp_pos);
    if (ret == 0) {
        DBG("RTSP close connection");
        on_close(client);
        return 0;
    } else if (ret < 0) {
        perror("RTSP read");
        return -1;
    }

    client->rtsp_pos += ret;

    uint8_t *buf = client->rtsp_buf;

    if (buf[0] == '$') {
        // interleaved data is:
        // '$' + channel byte + high length byte + low length byte + length data bytes
        uint16_t h = buf[2];
        uint16_t l = buf[3];
        uint16_t pktlen = ((h << 8) | l) + 4;
        // fprintf(stderr, "pktlen: %d\n", pktlen);
        if (client->rtsp_pos < pktlen) {
            /// need more data
            return 0;
        }

        ws_sendheader(client->dataep, pktlen, WS_FR_OP_BIN);
        ws_sendbody(client->dataep, buf, pktlen);

        memmove(buf, &buf[pktlen], client->rtsp_pos - pktlen);
        client->rtsp_pos -= pktlen;

        // sanity check. if we already have more bytes... it must be $ (more interleaved) or ascii (more normal data)
        if (client->rtsp_pos) {
            if (!(buf[0] == '$' || buf[0] == 'R')) {
                DBG("RTSP data error.");
                return -1;
            }
        }
    } else if (buf[0] == 'R') {
        const uint8_t *headerend = (const unsigned char *)strstr((char *)buf, "\r\n\r\n");
        if (!headerend) {
            if (client->rtsp_pos > 2000) { // FIXME
                dump("TOLARGE:", buf, client->rtsp_pos);
                DBG("SIZE: %d", client->rtsp_pos);
                return -1;
            }
            /// need more data
            return 0;
        }
        const int header_len = headerend - buf;

        uint16_t clen = 0;
        find_prop(buf, "Content-Length:", &clen);
        uint16_t pktlen = header_len + 4 + clen;
        if (client->rtsp_pos < pktlen) {
            /// need to gather more data
            return 0;
        }
        assert(client->rtsp_pos >= pktlen);

        dump("RTSP >> ", buf, pktlen);

        uint8_t header[MAX_HEAD_LEN];
        int idx = (client - gclient);
        int hlen = sprintf((char *)header, "WSP/1.1 %d %s\r\nchannel: %d\r\nseq: %d\r\nContent-Length: %d\r\n\r\n", 200, "OK", idx + 1, client->seq, pktlen);
        assert(hlen < MAX_HEAD_LEN);

        ws_sendheader(client->cfd, hlen + pktlen, WS_FR_OP_TXT);
        ws_sendbody(client->cfd, header, hlen);
        ws_sendbody(client->cfd, buf, pktlen);

        dump("WSP << ", header, hlen);

        memmove(buf, &buf[pktlen], client->rtsp_pos - pktlen);
        client->rtsp_pos -= pktlen;
    } else {
        DBG("RTSP unknown data.");
        return -1;
    }
    return 0;
}

static int agregate(client_t *client, uint8_t *payload, int len, uint8_t fin) {
    if (AG_BUF_SIZE - client->ag_pos < len) {
        DBG("WS not enough space to agregate fragmented packet");
        return -1;
    }

    memcpy(&client->ag_buf[client->ag_pos], payload, len);
    client->ag_pos += len;

    if (fin) {
        client->ag_buf[client->ag_pos] = '\0';
        on_message(client, client->ag_buf, client->ag_pos);
        client->ag_pos = 0;
    }

    return 0;
}

static int prepare_response(uint8_t *dst, uint8_t *key, uint8_t *proto) {
    SHA1Context ctx;
    uint8_t hash[SHA1HashSize];
    SHA1Reset(&ctx);
    SHA1Input(&ctx, key, WS_KEY_LEN);
    SHA1Input(&ctx, (uint8_t *)WS_MAGIC_STRING, WS_MAGIC_STRING_LEN);
    SHA1Result(&ctx, hash);

    char *next = stpcpy((char *)dst, WS_HS_ACCEPT);
    next = (char *)b64_enc((uint8_t *)next, 256, hash, SHA1HashSize); // FIXME
    next = stpcpy(next, "\r\nSec-WebSocket-Protocol: ");
    next = stpcpy(next, "chat"); // FIXME
    next = stpcpy(next, "\r\n\r\n");
    int len = (uint8_t *)next - dst;
    return len;
}

// client socket is ready to read
static int on_data(client_t *client) {
    if (client->ws_pos >= WS_BUF_SIZE) {
        DBG("WS data overflow.");
        return -1;
    }

    ssize_t ret = read(client->cfd, client->ws_buf + client->ws_pos, WS_BUF_SIZE - client->ws_pos);
    if (ret == 0) {
        DBG("WS remote closed connection.");
        on_close(client);
        return 0;
    } else if (ret < 0) {
        perror("sock");
        DBG("WS socket error.");
        return -1;
    }

    client->ws_pos += ret;
    client->ws_buf[client->ws_pos] = '\0';

    if (!client->isupgraded) {
        // nust be an http request
        // GET / HTTP/1.1
        // Host: localhost:8555
        // User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
        // Accept: */*
        // Accept-Language: en-US,en;q=0.5
        // Accept-Encoding: gzip, deflate, br
        // Sec-WebSocket-Version: 13
        // Origin: null
        // Sec-WebSocket-Protocol: chat
        // Sec-WebSocket-Extensions: permessage-deflate
        // Sec-WebSocket-Key: 1/Za8MkAzhzd2QZHodL5gg==
        // Connection: keep-alive, Upgrade
        // Sec-Fetch-Dest: websocket
        // Sec-Fetch-Mode: websocket
        // Sec-Fetch-Site: cross-site
        // Pragma: no-cache
        // Cache-Control: no-cache
        // Upgrade: websocket

        uint8_t *headerend = (uint8_t *)strstr((char *)client->ws_buf, "\r\n\r\n");
        if (headerend) {
            const int headerlen = (headerend - client->ws_buf) + 4;
            *headerend = '\0';
            if (headerlen != client->ws_pos) {
                DBG("WS recieved more dat that expected.");
                return -1;
            }
            // have full header
            // get Sec-WebSocket-Protocol:
            uint8_t *proto = get_header_option("Sec-WebSocket-Protocol:", client->ws_buf);
            uint8_t *key = get_header_option("Sec-WebSocket-Key:", client->ws_buf);
            uint8_t *upgrade = get_header_option("Upgrade:", client->ws_buf);
            // get Sec-WebSocket-Key:
            // get Upgrade:
            if (!proto) {
                DBG("WS missing required headers Sec-WebSocket-Protocol.");
                return -1;
            }
            if (!key) {
                DBG("WS missing required header Sec-WebSocket-Key.");
                return -1;
            }
            if (!upgrade) {
                DBG("WS missing required header upgrade.");
                return -1;
            }

            terminate_option(key);

            int len = prepare_response(client->ag_buf, key, proto);
            dump("RESP:", client->ag_buf, len);
            write(client->cfd, client->ag_buf, len);

            memmove(client->ws_buf, &client->ws_buf[headerlen], client->ws_pos - headerlen);
            client->ws_pos = 0;

            client->isupgraded = 1;
        }
    } else {
        if (client->ws_pos < 2) {
            // wait for more data
            return 0;
        }
        /// ... the display of bits are reversed here...
        // 0                   1                   2                   3
        // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        //+-+-+-+-+-------+-+-------------+-------------------------------+
        //|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
        //|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
        //|N|V|V|V|       |S|             |   (if payload len==126/127)   |
        //| |1|2|3|       |K|             |                               |
        //+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
        //|     Extended payload length continued, if payload len == 127  |
        //+ - - - - - - - - - - - - - - - +-------------------------------+
        //|                               |Masking-key, if MASK set to 1  |
        //+-------------------------------+-------------------------------+
        //| Masking-key (continued)       |          Payload Data         |
        //+-------------------------------- - - - - - - - - - - - - - - - +
        //:                     Payload Data continued ...                :
        //+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
        //|                     Payload Data continued ...                |
        //+---------------------------------------------------------------+

        // 00100000 01010100 01000101 01000111

        uint8_t *buf = (uint8_t *)client->ws_buf;
        if (buf[0] & 0x70) {
            DBG("WS reserved bits are set.");
            return -1;
        }

        // buf[0] -> fin rsv1 rsv2 rsv3 op etc
        uint8_t fin = buf[0] & 0x01;
        uint8_t op = buf[0] & 0x0f;
        uint8_t mask = (buf[1] & 0x80) >> 7;
        uint64_t pllen = buf[1] & 0x7f;

        if (!mask) {
            DBG("WS client failed to set mask bit.");
            return -1;
        }

        int idx = 2;
        if (pllen == 126) {
            uint64_t h = buf[idx + 0];
            uint64_t l = buf[idx + 1];
            pllen = (h << 8) | l;
            idx += 2;
        } else if (pllen == 127) {
            uint64_t x = buf[idx + 0];
            uint64_t e = buf[idx + 1];
            uint64_t h = buf[idx + 2];
            uint64_t l = buf[idx + 3];
            pllen = (x << 24) | (e << 16) | (h << 8) | l;
            idx += 8;
        } else {
            // small packet
        }

        int pktlen = 2 + 4 + pllen;
        if (client->ws_pos < pktlen) {
            // wait for more data
            return 0;
        }

        uint8_t mbyte[4];
        mbyte[0] = buf[idx++];
        mbyte[1] = buf[idx++];
        mbyte[2] = buf[idx++];
        mbyte[3] = buf[idx++];

        uint8_t *payload = &buf[idx];
        for (int i = 0; i < pllen; i++) {
            payload[i] ^= mbyte[i % 4];
        }

        // if is control frame assert not fragmented frame
        if (op == WS_FR_OP_PING || op == WS_FR_OP_PONG) {
            if (fin == 0) {
                DBG("WS Ilegal fragmented websocket control frame.");
                return -1;
            }
        }

        switch (op) {
        case WS_FR_OP_TXT:
        case WS_FR_OP_BIN:
            // concatenate and handle
            agregate(client, payload, pllen, fin);
            client->ws_pos = 0;
            break;
        case WS_FR_OP_CONT:
            // concatenate and handle
            agregate(client, payload, pllen, fin);
            client->ws_pos = 0;
            break;
        case WS_FR_OP_PING:
            // unmask the mask bit. change the op to pong
            buf[0] = (buf[0] & 0x0f) | WS_FR_OP_PONG;
            buf[1] &= 0x7f;
            // send back
            write(client->cfd, client->ws_buf, pktlen);
            break;
        case WS_FR_OP_PONG:
            DBG("WS unexpected pong frame reciever from websocket client.");
            return -1;
        case WS_FR_OP_CLOSE:
            // send back as is
            write(client->cfd, client->ws_buf, pktlen);
            on_close(client);
            return 0;
        default:
            DBG("WS unsupported op code: 0x%02x.", op);
            return -1;
        }
    }

    return 0;
}

// there is a new connection waiting
static int on_accept(int sfd) {
    client_t *client = NULL;
    for (int i = 0; i < MAXCLIENTS; i++) {
        if (gclient[i].cfd > 0)
            continue;

        client = &gclient[i];
        break;
    }

    if (!client) {
        DBG("no available client slots");
        return -1;
    }

    struct sockaddr_storage addr;
    socklen_t addrlen;
    int cfd = accept(sfd, (struct sockaddr *)&addr, &addrlen);
    if (cfd < 0) {
        return cfd;
    }

    if (on_connect(client, cfd)) {
        close(cfd);
    }

    return 0;
}

static void shutdown_now(int _) {
    // FIXME: close all open websocket connections?
    fprintf(stderr, "SHUTDOWN!\n");
    exit(0);
}

int main(int argc, char **argv) {
    // get config
    const char *ENV_BINDHOST = getenv_dflt("BINDHOST", "0.0.0.0");
    const char *ENV_BINDPORT = getenv_dflt("BINDPORT", "8555");
    const char *ENV_LISTENBACKLOG = getenv_dflt("LISTENBACKLOG", "8");

    // graceful shutdown
    struct sigaction sa;
    sa.sa_handler = shutdown_now;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("Failed to attach SIGTERM handler");
        return -1;
    }

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Failed to attach SIGINT handler");
        return -1;
    }

    // init local data
    memset(gclient, 0, sizeof(client_t) * MAXCLIENTS);

    // open socket
    const int sfd = ws_bind_socket(ENV_BINDHOST, ENV_BINDPORT);
    if (sfd < 0) {
        perror("Unable to bind socket");
        return -1;
    }

    int err = listen(sfd, atoi(ENV_LISTENBACKLOG));
    if (err < 0) {
        perror("Unable to listen");
        return -1;
    }

    // main loop
    struct timeval tv;
    fd_set fdread;
    fd_set fdexcep;
    while (1) {
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        FD_ZERO(&fdread);
        FD_SET(sfd, &fdread);
        int maxfd = sfd;
        for (int i = 0; i < MAXCLIENTS; i++) {
            if (gclient[i].cfd > 0) {
                if (gclient[i].cfd > maxfd)
                    maxfd = gclient[i].cfd;

                FD_SET(gclient[i].cfd, &fdread);
                FD_SET(gclient[i].cfd, &fdexcep);
            }
            if (gclient[i].rtsp > 0) {
                if (gclient[i].rtsp > maxfd)
                    maxfd = gclient[i].rtsp;

                FD_SET(gclient[i].rtsp, &fdread);
                FD_SET(gclient[i].rtsp, &fdexcep);
            }
        }

        err = select(maxfd + 1, &fdread, NULL, &fdexcep, &tv);
        if (err < 0) {
            perror("Select");
            return -1;
        }

        if (err == 0) {
            // select timed out... no clients ready.
            continue;
        }

        // check listening socket for fresh clients or exceptions
        if (FD_ISSET(sfd, &fdexcep)) {
            DBG("main socket exception");
            break;
        }

        if (FD_ISSET(sfd, &fdread)) {
            err = on_accept(sfd);
            if (err) {
                DBG("bad accept");
                return -1;
            }
        }

        // check client sockets for data or exceptions
        for (int i = 0; i < MAXCLIENTS; i++) {
            if (gclient[i].cfd <= 0)
                continue;

            if (FD_ISSET(gclient[i].cfd, &fdexcep)) {
                on_close(&gclient[i]);
            }

            if (gclient[i].cfd <= 0)
                continue;

            if (FD_ISSET(gclient[i].cfd, &fdread)) {
                if (on_data(&gclient[i])) {
                    on_close(&gclient[i]);
                }
            }
        }

        // check rtsp sockets for data or exceptions
        for (int i = 0; i < MAXCLIENTS; i++) {
            if (gclient[i].rtsp <= 0)
                continue;

            if (FD_ISSET(gclient[i].rtsp, &fdexcep)) {
                on_close(&gclient[i]);
            }

            if (gclient[i].rtsp <= 0)
                continue;

            if (FD_ISSET(gclient[i].rtsp, &fdread)) {
                if (on_rtsp_data(&gclient[i])) {
                    on_close(&gclient[i]);
                }
            }
        }
    }

    return 0;
}
