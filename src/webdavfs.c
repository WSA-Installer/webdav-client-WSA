/* webdavfs - full read-write WebDAV client as a FUSE filesystem for WSA.
   Static musl build via zig cc; raw FUSE kernel protocol (no libfuse).
   Methods: OPTIONS PROPFIND HEAD GET PUT DELETE MKCOL COPY MOVE.
   Features: HTTP Basic auth, HTTPS (mbedTLS), directory cache, Range reads,
   buffered writes flushed with PUT, -d daemon mode, --selftest. */
#ifndef VERSION
#define VERSION "0.2.0"
#endif
#ifndef WEBDAVFS_WITH_TLS
#define WEBDAVFS_WITH_TLS 1
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/fuse.h>

#if WEBDAVFS_WITH_TLS
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/net_sockets.h>
#endif

#define FUSE_VERSION_MAJOR 7
#define FUSE_VERSION_MINOR 31
#define MAX_WRITE 131072u
#define MAX_HEADER 16384u
#define MAX_BODY 67108864u
#define MAX_LISTING 33554432u
#define DEFAULT_MAX_WRITE_FILE (256u * 1024u * 1024u)
#define DEFAULT_CACHE_TTL 2
#define WINDOW_CAP (1024u * 1024u)
#define CONNECT_TIMEOUT_S 3
#define IO_TIMEOUT_S 15
#define USER_AGENT "webdavfs/" VERSION

static int g_stop = 0;
static int g_verbose = 0;
static FILE *g_logf = NULL;

static void logmsg(const char *fmt, ...) {
    va_list ap;
    char line[1024];
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    fprintf(stderr, "[%02d:%02d:%02d] webdavfs: %s\n",
            tmv.tm_hour, tmv.tm_min, tmv.tm_sec, line);
    if (g_logf) {
        fprintf(g_logf, "[%02d:%02d:%02d] %s\n",
                tmv.tm_hour, tmv.tm_min, tmv.tm_sec, line);
        fflush(g_logf);
    }
}

static void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) { logmsg("out of memory (%zu)", n); abort(); }
    return p;
}

static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) { logmsg("out of memory (%zu)", n); abort(); }
    return q;
}

static char *xstrdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = xmalloc(n);
    memcpy(p, s, n);
    return p;
}

static void on_signal(int sig) { (void)sig; g_stop = 1; }

/* ------------------------------------------------------------------ base64 */
static char *b64_encode(const unsigned char *in, size_t len) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, o = 0;
    char *out = xmalloc(((len + 2) / 3) * 4 + 1);
    for (i = 0; i + 2 < len; i += 3) {
        unsigned v = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
        out[o++] = tbl[(v >> 18) & 63];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = tbl[(v >> 6) & 63];
        out[o++] = tbl[v & 63];
    }
    if (i < len) {
        unsigned v = in[i] << 16;
        if (i + 1 < len) v |= in[i + 1] << 8;
        out[o++] = tbl[(v >> 18) & 63];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = (i + 1 < len) ? tbl[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = 0;
    return out;
}

/* -------------------------------------------------------------- url helpers */
typedef struct {
    int https;
    char *host;
    int port;
    char *base;
    char *user;
    char *pass;
} webdav_t;

static webdav_t g_wd;

static int is_unreserved(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
           c == '~';
}

static char *url_encode_path(const char *s) {
    size_t n = strlen(s), i, o = 0;
    char *out = xmalloc(n * 3 + 1);
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (is_unreserved(c) || c == '/') {
            out[o++] = (char)c;
        } else {
            static const char hex[] = "0123456789ABCDEF";
            out[o++] = '%';
            out[o++] = hex[c >> 4];
            out[o++] = hex[c & 15];
        }
    }
    out[o] = 0;
    return out;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static char *url_decode(const char *s) {
    size_t n = strlen(s), i, o = 0;
    char *out = xmalloc(n + 1);
    for (i = 0; i < n; i++) {
        if (s[i] == '%' && i + 2 < n) {
            int h = hexval(s[i + 1]), l = hexval(s[i + 2]);
            if (h >= 0 && l >= 0) {
                out[o++] = (char)((h << 4) | l);
                i += 2;
                continue;
            }
        }
        out[o++] = s[i];
    }
    out[o] = 0;
    return out;
}

static char *xml_unescape(const char *s) {
    size_t n = strlen(s), i, o = 0;
    char *out = xmalloc(n + 1);
    for (i = 0; i < n; i++) {
        if (s[i] == '&') {
            if (!strncmp(s + i, "&amp;", 5)) { out[o++] = '&'; i += 4; continue; }
            if (!strncmp(s + i, "&lt;", 4)) { out[o++] = '<'; i += 3; continue; }
            if (!strncmp(s + i, "&gt;", 4)) { out[o++] = '>'; i += 3; continue; }
            if (!strncmp(s + i, "&quot;", 6)) { out[o++] = '"'; i += 5; continue; }
            if (!strncmp(s + i, "&apos;", 6)) { out[o++] = '\''; i += 5; continue; }
            if (s[i + 1] == '#') {
                int code = 0, ok = 1;
                size_t j = i + 2;
                if (j < n && (s[j] == 'x' || s[j] == 'X')) {
                    j++;
                    for (; s[j] && s[j] != ';'; j++) {
                        int h = hexval(s[j]);
                        if (h < 0) { ok = 0; break; }
                        code = code * 16 + h;
                    }
                } else {
                    for (; s[j] && s[j] >= '0' && s[j] <= '9'; j++)
                        code = code * 10 + (s[j] - '0');
                }
                if (ok && code > 0 && s[j] == ';' && code < 0x80) {
                    out[o++] = (char)code;
                    i = j;
                    continue;
                }
            }
        }
        out[o++] = s[i];
    }
    out[o] = 0;
    return out;
}

static int parse_webdav_url(const char *url) {
    const char *p = url;
    memset(&g_wd, 0, sizeof g_wd);
    if (!strncmp(p, "https://", 8)) { g_wd.https = 1; p += 8; g_wd.port = 443; }
    else if (!strncmp(p, "http://", 7)) { p += 7; g_wd.port = 80; }
    else { logmsg("URL must start with http:// or https://"); return -1; }
    const char *at = strchr(p, '@');
    const char *slash = strchr(p, '/');
    if (at && (!slash || at < slash)) {
        const char *colon = memchr(p, ':', (size_t)(at - p));
        if (colon) {
            g_wd.user = strndup(p, (size_t)(colon - p));
            g_wd.pass = strndup(colon + 1, (size_t)(at - colon - 1));
        } else {
            g_wd.user = strndup(p, (size_t)(at - p));
        }
        p = at + 1;
        slash = strchr(p, '/');
    }
    const char *hend = slash ? slash : p + strlen(p);
    const char *colon = memchr(p, ':', (size_t)(hend - p));
    if (colon) {
        g_wd.host = strndup(p, (size_t)(colon - p));
        g_wd.port = atoi(colon + 1);
    } else {
        g_wd.host = strndup(p, (size_t)(hend - p));
    }
    if (!g_wd.host[0]) { logmsg("empty host in URL"); return -1; }
    if (!slash) {
        g_wd.base = xstrdup("/");
    } else {
        g_wd.base = xstrdup(slash);
    }
    size_t bl = strlen(g_wd.base);
    if (bl == 0 || g_wd.base[bl - 1] != '/') {
        g_wd.base = xrealloc(g_wd.base, bl + 2);
        g_wd.base[bl] = '/';
        g_wd.base[bl + 1] = 0;
    }
    return 0;
}

static char *join_path(const char *rel) {
    size_t bl = strlen(g_wd.base), rl = strlen(rel);
    char *full = xmalloc(bl + rl + 2);
    memcpy(full, g_wd.base, bl);
    if (rl) {
        if (rel[0] == '/') { memcpy(full + bl, rel + 1, rl); full[bl + rl] = 0; }
        else { memcpy(full + bl, rel, rl); full[bl + rl] = 0; }
    } else {
        full[bl] = 0;
    }
    if (full[0] != '/') {
        char *fix = xmalloc(strlen(full) + 2);
        fix[0] = '/';
        strcpy(fix + 1, full);
        free(full);
        full = fix;
    }
    return full;
}

/* ------------------------------------------------------------------- http */
typedef struct {
    int status;
    char *body;
    size_t body_len;
    long content_length;
    char last_modified[64];
    int chunked;
} http_resp_t;

static int g_ssl_verify = 0;
static char *g_ca_path = NULL;

#if WEBDAVFS_WITH_TLS
static mbedtls_ssl_context g_ssl;
static mbedtls_ssl_config g_ssl_conf;
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;
static mbedtls_x509_crt g_ca;
static int g_tls_ready = 0;

static int tls_init(void) {
    int ret;
    const char *pers = "webdavfs";
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_drbg);
    mbedtls_ssl_init(&g_ssl);
    mbedtls_ssl_config_init(&g_ssl_conf);
    mbedtls_x509_crt_init(&g_ca);
    ret = mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (ret != 0) { logmsg("tls: ctr_drbg_seed failed (-0x%x)", -ret); return -1; }
    ret = mbedtls_ssl_config_defaults(&g_ssl_conf, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) { logmsg("tls: config_defaults failed (-0x%x)", -ret); return -1; }
    mbedtls_ssl_conf_rng(&g_ssl_conf, mbedtls_ctr_drbg_random, &g_drbg);
    if (g_ssl_verify) {
        const char *cap = g_ca_path ? g_ca_path
                                    : "/etc/ssl/certs/ca-certificates.crt";
        if (mbedtls_x509_crt_parse_file(&g_ca, cap) == 0) {
            mbedtls_ssl_conf_ca_chain(&g_ssl_conf, &g_ca, NULL);
            mbedtls_ssl_conf_authmode(&g_ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        } else {
            logmsg("tls: cannot parse CA file %s, verification disabled", cap);
            mbedtls_ssl_conf_authmode(&g_ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
        }
    } else {
        mbedtls_ssl_conf_authmode(&g_ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
    }
    mbedtls_ssl_setup(&g_ssl, &g_ssl_conf);
    g_tls_ready = 1;
    return 0;
}

static int tls_start(int fd) {
    int ret;
    if (!g_tls_ready && tls_init() != 0) return -1;
    mbedtls_ssl_session_reset(&g_ssl);
    mbedtls_ssl_set_hostname(&g_ssl, g_wd.host);
    mbedtls_net_context net;
    net.fd = fd;
    mbedtls_ssl_set_bio(&g_ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);
    while ((ret = mbedtls_ssl_handshake(&g_ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            logmsg("tls: handshake failed (-0x%x)", -ret);
            return -1;
        }
    }
    return 0;
}

static int tls_read(unsigned char *buf, size_t n) {
    int r = mbedtls_ssl_read(&g_ssl, buf, n);
    if (r < 0 && r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE)
        return -1;
    return r;
}

static int tls_write(const unsigned char *buf, size_t n) {
    int r = mbedtls_ssl_write(&g_ssl, buf, n);
    if (r < 0 && r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE)
        return -1;
    return r;
}
#endif

static int net_read(int fd, unsigned char *buf, size_t n) {
#if WEBDAVFS_WITH_TLS
    if (*(volatile int *)&g_wd.https) return tls_read(buf, n);
#endif
    ssize_t r = recv(fd, buf, n, 0);
    return (int)r;
}

static int net_write(int fd, const unsigned char *buf, size_t n) {
#if WEBDAVFS_WITH_TLS
    if (*(volatile int *)&g_wd.https) return tls_write(buf, n);
#endif
    ssize_t r = send(fd, buf, n, MSG_NOSIGNAL);
    return (int)r;
}

static int http_connect(void) {
    char portstr[16];
    struct addrinfo hints, *res = NULL, *ai;
    int fd = -1;
    snprintf(portstr, sizeof portstr, "%d", g_wd.port);
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(g_wd.host, portstr, &hints, &res) != 0) {
        logmsg("dns failed for %s", g_wd.host);
        return -1;
    }
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        struct timeval tv = { .tv_sec = CONNECT_TIMEOUT_S, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) { logmsg("connect to %s:%d failed", g_wd.host, g_wd.port); return -1; }
    struct timeval tv = { .tv_sec = IO_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
#if WEBDAVFS_WITH_TLS
    if (*(volatile int *)&g_wd.https) {
        if (tls_start(fd) != 0) { close(fd); return -1; }
    }
#else
    if (g_wd.https) { logmsg("https support not compiled in"); close(fd); return -1; }
#endif
    return fd;
}

static int write_all(int fd, const unsigned char *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        int w = net_write(fd, buf + off, n - off);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static int read_line(int fd, char *buf, size_t cap) {
    size_t o = 0;
    for (;;) {
        unsigned char c;
        int r = net_read(fd, &c, 1);
        if (r <= 0) return -1;
        if (c == '\n') {
            if (o && buf[o - 1] == '\r') o--;
            buf[o] = 0;
            return (int)o;
        }
        if (o + 1 < cap) buf[o++] = (char)c;
    }
}

static const char *find_header_end(const char *buf, size_t n, size_t *hdr_len) {
    size_t i;
    for (i = 3; i < n; i++) {
        if (buf[i - 3] == '\r' && buf[i - 2] == '\n' &&
            buf[i - 1] == '\r' && buf[i] == '\n') {
            *hdr_len = i + 1;
            return buf;
        }
    }
    return NULL;
}

typedef struct {
    const char *method;
    const char *rel_path;
    const char *extra_headers;
    const unsigned char *body;
    size_t body_len;
    int want_body;
    long range_off;
    long range_len;
    size_t body_cap;
} http_req_t;

static int http_do(const http_req_t *req, http_resp_t *resp) {
    memset(resp, 0, sizeof *resp);
    resp->content_length = -1;
    int fd = http_connect();
    if (fd < 0) return -1;
    char *abspath = url_encode_path(join_path(req->rel_path));
    char *joined = join_path(req->rel_path);
    free(joined);
    char head[MAX_HEADER];
    int n = snprintf(head, sizeof head,
                     "%s %s HTTP/1.1\r\n"
                     "Host: %s:%d\r\n"
                     "User-Agent: " USER_AGENT "\r\n"
                     "Connection: close\r\n"
                     "Accept: */*\r\n",
                     req->method, abspath, g_wd.host, g_wd.port);
    if (g_wd.user) {
        char *creds_raw = malloc(strlen(g_wd.user) + (g_wd.pass ? strlen(g_wd.pass) : 0) + 2);
        if (creds_raw) {
            if (g_wd.pass)
                sprintf(creds_raw, "%s:%s", g_wd.user, g_wd.pass);
            else
                sprintf(creds_raw, "%s:", g_wd.user);
            char *b64 = b64_encode((unsigned char *)creds_raw, strlen(creds_raw));
            n += snprintf(head + n, sizeof head - (size_t)n,
                          "Authorization: Basic %s\r\n", b64);
            free(b64);
            free(creds_raw);
        }
    }
    if (req->extra_headers)
        n += snprintf(head + n, sizeof head - (size_t)n, "%s", req->extra_headers);
    if (req->body && req->body_len)
        n += snprintf(head + n, sizeof head - (size_t)n,
                      "Content-Length: %zu\r\n", req->body_len);
    if (req->range_len > 0)
        n += snprintf(head + n, sizeof head - (size_t)n,
                      "Range: bytes=%ld-%ld\r\n", req->range_off,
                      req->range_off + req->range_len - 1);
    n += snprintf(head + n, sizeof head - (size_t)n, "\r\n");
    if (n <= 0 || (size_t)n >= sizeof head ||
        write_all(fd, (unsigned char *)head, (size_t)n) != 0) {
        free(abspath);
        close(fd);
        return -1;
    }
    if (req->body && req->body_len &&
        write_all(fd, req->body, req->body_len) != 0) {
        free(abspath);
        close(fd);
        return -1;
    }
    free(abspath);

    char *acc = xmalloc(MAX_HEADER);
    size_t acc_len = 0;
    size_t hdr_len = 0;
    const char *he;
    while (acc_len < MAX_HEADER - 1) {
        int r = net_read(fd, (unsigned char *)acc + acc_len,
                         MAX_HEADER - 1 - acc_len);
        if (r <= 0) { free(acc); close(fd); return -1; }
        acc_len += (size_t)r;
        he = find_header_end(acc, acc_len, &hdr_len);
        if (he) break;
    }
    if (!he) { free(acc); close(fd); logmsg("response headers too large"); return -1; }
    acc[acc_len] = 0;
    if (sscanf(acc, "HTTP/%*s %d", &resp->status) != 1) {
        free(acc); close(fd); return -1;
    }
    resp->chunked = 0;
    {
        char *p = acc;
        while (p && p < acc + hdr_len) {
            char *nl = strstr(p, "\r\n");
            if (nl) *nl = 0;
            if (!strncasecmp(p, "Content-Length:", 15))
                resp->content_length = atol(p + 15);
            else if (!strncasecmp(p, "Transfer-Encoding:", 18) &&
                     strstr(p, "chunked"))
                resp->chunked = 1;
            else if (!strncasecmp(p, "Last-Modified:", 14)) {
                char *v = p + 14;
                while (*v == ' ') v++;
                snprintf(resp->last_modified, sizeof resp->last_modified, "%s", v);
            }
            p = nl ? nl + 2 : NULL;
        }
    }
    size_t body_cap = req->body_cap ? req->body_cap : MAX_BODY;
    unsigned char *body = xmalloc(body_cap + 1);
    size_t body_len = 0;
    size_t pending = acc_len > hdr_len ? acc_len - hdr_len : 0;
    if (pending) {
        if (pending > body_cap) { free(acc); free(body); close(fd); return -1; }
        memcpy(body, acc + hdr_len, pending);
        body_len = pending;
    }
    free(acc);
    if (resp->chunked) {
        char *buf = xmalloc(body_cap + 1);
        size_t out_len = 0;
        char line[64];
        for (;;) {
            if (read_line(fd, line, sizeof line) < 0) { free(buf); free(body); close(fd); return -1; }
            char *endp = NULL;
            unsigned long sz = strtoul(line, &endp, 16);
            if (endp == line) { free(buf); free(body); close(fd); return -1; }
            if (sz == 0) break;
            if (out_len + sz > body_cap) { free(buf); free(body); close(fd); return -1; }
            size_t got = 0;
            while (got < sz) {
                int r = net_read(fd, (unsigned char *)(buf + got), sz - got);
                if (r <= 0) { free(buf); free(body); close(fd); return -1; }
                got += (size_t)r;
            }
            memcpy(body + out_len, buf, sz);
            out_len += sz;
            if (read_line(fd, line, sizeof line) < 0) { free(buf); free(body); close(fd); return -1; }
        }
        free(buf);
        body_len = out_len;
    } else if (req->want_body && resp->content_length >= 0) {
        size_t want = (size_t)resp->content_length;
        if (want > body_cap) { free(body); close(fd); return -1; }
        while (body_len < want) {
            int r = net_read(fd, body + body_len, want - body_len);
            if (r <= 0) break;
            body_len += (size_t)r;
        }
    } else if (req->want_body) {
        while (body_len < body_cap) {
            int r = net_read(fd, body + body_len, body_cap - body_len);
            if (r <= 0) break;
            body_len += (size_t)r;
        }
    }
    body[body_len] = 0;
    resp->body = (char *)body;
    resp->body_len = body_len;
    close(fd);
    if (g_verbose)
        logmsg("%s %s -> %d (%zu bytes)", req->method, req->rel_path,
               resp->status, resp->body_len);
    return 0;
}

static void resp_free(http_resp_t *r) {
    free(r->body);
    r->body = NULL;
}

/* --------------------------------------------------------------- webdav ops */
typedef struct {
    char *name;
    int is_dir;
    long long size;
    time_t mtime;
} dent_t;

static time_t parse_http_date(const char *s) {
    struct tm tmv;
    memset(&tmv, 0, sizeof tmv);
    const char *p = s;
    if ((p = strptime(p, "%a, %d %b %Y %H:%M:%S", &tmv)) != NULL)
        return timegm(&tmv);
    if ((p = strptime(s, "%A, %d-%b-%y %H:%M:%S", &tmv)) != NULL)
        return timegm(&tmv);
    if (strptime(s, "%a %b %d %H:%M:%S %Y", &tmv) != NULL)
        return timegm(&tmv);
    return 0;
}

static char *href_to_name(const char *href) {
    char *work = xstrdup(href);
    char *scheme = strstr(work, "://");
    if (scheme) {
        char *slash = strchr(scheme + 3, '/');
        if (slash) memmove(work, slash, strlen(slash) + 1);
        else { work[0] = '/'; work[1] = 0; }
    }
    size_t n = strlen(work);
    while (n && work[n - 1] == '/') work[--n] = 0;
    const char *slash2 = strrchr(work, '/');
    const char *raw = slash2 ? slash2 + 1 : work;
    char *dec = url_decode(raw);
    free(work);
    return dec;
}

static int xml_name_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '-';
}

static const char *xml_bare_name(const char *lt) {
    if (*lt != '<') return NULL;
    const char *name = lt + 1;
    if (*name == '/') name++;
    const char *scan = name;
    while (*scan && xml_name_char(*scan)) scan++;
    if (*scan == ':') name = scan + 1;
    return name;
}

static const char *tag_body(const char *p, const char *tag, char *out, size_t cap) {
    size_t tlen = strlen(tag);
    const char *q = p;
    const char *start = NULL;
    const char *bare = NULL;
    while ((q = strchr(q, '<')) != NULL) {
        if (q[1] == '/') { q++; continue; }
        const char *name = xml_bare_name(q);
        if (name && !strncasecmp(name, tag, tlen)) {
            const char *after = name + tlen;
            if (*after == '>' || *after == ' ' || *after == '/' ||
                *after == '\t' || *after == '\r' || *after == '\n') {
                start = q;
                bare = name;
                break;
            }
        }
        q++;
    }
    if (!start) return NULL;
    const char *gt = strchr(start, '>');
    if (!gt) return NULL;
    if (bare[tlen] == '/') {
        out[0] = 0;
        return gt + 1;
    }
    const char *end = NULL;
    for (const char *r = gt + 1; (r = strchr(r, '<')) != NULL; r++) {
        if (r[1] != '/') continue;
        const char *name = xml_bare_name(r);
        if (name && !strncasecmp(name, tag, tlen) && name[tlen] == '>') {
            end = r;
            break;
        }
    }
    if (!end) return NULL;
    size_t len = (size_t)(end - (gt + 1));
    if (len >= cap) len = cap - 1;
    memcpy(out, gt + 1, len);
    out[len] = 0;
    const char *close_gt = strchr(end, '>');
    return close_gt ? close_gt + 1 : end + 1;
}

static int propfind_list(const char *rel, dent_t **out_ents, size_t *out_n) {
    static const char body_xml[] =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<D:propfind xmlns:D=\"DAV:\"><D:prop>"
        "<D:resourcetype/><D:getcontentlength/><D:getlastmodified/>"
        "</D:prop></D:propfind>";
    http_req_t req = {
        .method = "PROPFIND",
        .rel_path = rel,
        .extra_headers = "Depth: 1\r\nContent-Type: application/xml\r\n",
        .body = (const unsigned char *)body_xml,
        .body_len = sizeof body_xml - 1,
        .want_body = 1,
        .body_cap = MAX_LISTING,
    };
    http_resp_t resp;
    if (http_do(&req, &resp) != 0) return -1;
    int rc = -1;
    if (resp.status == 207 || resp.status == 200) {
        dent_t *ents = NULL;
        size_t n = 0, cap = 0;
        const char *p = resp.body;
        char href[2048], coll[16], clen[32], cmod[64];
        int first = 1;
        while ((p = tag_body(p, "href", href, sizeof href)) != NULL) {
            const char *q = p;
            coll[0] = 0;
            clen[0] = 0;
            cmod[0] = 0;
            const char *nxt = q;
            while ((nxt = strchr(nxt, '<')) != NULL) {
                const char *nm = xml_bare_name(nxt);
                if (nm && !strncasecmp(nm, "href", 4) &&
                    (nm[4] == '>' || nm[4] == ' ' || nm[4] == '/')) break;
                if (nxt[1] == '/' && nm && !strncasecmp(nm, "response", 8) &&
                    nm[8] == '>') break;
                if (nm && !strncasecmp(nm, "collection", 10) &&
                    (nm[10] == '>' || nm[10] == ' ' || nm[10] == '/')) {
                    if (nxt[1] != '/') strcpy(coll, "1");
                    nxt++;
                    continue;
                }
                if (nm && !strncasecmp(nm, "getcontentlength", 16) &&
                    (nm[16] == '>' || nm[16] == ' ')) {
                    if (tag_body(nxt, "getcontentlength", clen, sizeof clen))
                        continue;
                }
                if (nm && !strncasecmp(nm, "getlastmodified", 15) &&
                    (nm[15] == '>' || nm[15] == ' ')) {
                    if (tag_body(nxt, "getlastmodified", cmod, sizeof cmod))
                        continue;
                }
                nxt++;
            }
            char *full = xml_unescape(href);
            if (first) { first = 0; free(full); continue; }
            dent_t d;
            memset(&d, 0, sizeof d);
            d.name = href_to_name(full);
            d.is_dir = coll[0] != 0;
            d.size = clen[0] ? atoll(clen) : 0;
            d.mtime = cmod[0] ? parse_http_date(cmod) : 0;
            free(full);
            if (d.name[0] == 0 || !strcmp(d.name, ".") || !strcmp(d.name, "..")) {
                free(d.name);
                continue;
            }
            if (n == cap) {
                cap = cap ? cap * 2 : 16;
                ents = xrealloc(ents, cap * sizeof *ents);
            }
            ents[n++] = d;
        }
        *out_ents = ents;
        *out_n = n;
        rc = 0;
    }
    resp_free(&resp);
    return rc;
}

static int propfind_self(const char *rel, int *is_dir, long long *size,
                         time_t *mtime) {
    static const char body_xml[] =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<D:propfind xmlns:D=\"DAV:\"><D:prop>"
        "<D:resourcetype/><D:getcontentlength/><D:getlastmodified/>"
        "</D:prop></D:propfind>";
    http_req_t req = {
        .method = "PROPFIND",
        .rel_path = rel,
        .extra_headers = "Depth: 0\r\nContent-Type: application/xml\r\n",
        .body = (const unsigned char *)body_xml,
        .body_len = sizeof body_xml - 1,
        .want_body = 1,
        .body_cap = 1048576,
    };
    http_resp_t resp;
    if (http_do(&req, &resp) != 0) return -1;
    int rc = -1;
    if (resp.status == 207 || resp.status == 200) {
        char coll[16], clen[32], cmod[64];
        coll[0] = clen[0] = cmod[0] = 0;
        const char *p = resp.body;
        char href[2048];
        p = tag_body(p, "href", href, sizeof href);
        if (p) {
            tag_body(p, "resourcetype", coll, sizeof coll);
            const char *scan = resp.body;
            if (strstr(scan, "<D:collection") || strstr(scan, "<d:collection") ||
                strstr(scan, "<collection"))
                *is_dir = 1;
            else
                *is_dir = 0;
            tag_body(resp.body, "getcontentlength", clen, sizeof clen);
            tag_body(resp.body, "getlastmodified", cmod, sizeof cmod);
            *size = clen[0] ? atoll(clen) : 0;
            *mtime = cmod[0] ? parse_http_date(cmod) : 0;
            rc = 0;
        }
    }
    resp_free(&resp);
    return rc;
}

static int head_self(const char *rel, long long *size, time_t *mtime) {
    http_req_t req = { .method = "HEAD", .rel_path = rel, .want_body = 0 };
    http_resp_t resp;
    if (http_do(&req, &resp) != 0) return -1;
    int rc = -1;
    if (resp.status == 200) {
        *size = resp.content_length >= 0 ? resp.content_length : 0;
        *mtime = resp.last_modified[0] ? parse_http_date(resp.last_modified) : 0;
        rc = 0;
    }
    resp_free(&resp);
    return rc;
}

static int get_range(const char *rel, long long off, long long len,
                     unsigned char **out, size_t *out_len) {
    http_req_t req = {
        .method = "GET",
        .rel_path = rel,
        .want_body = 1,
        .range_off = off,
        .range_len = len,
        .body_cap = (size_t)len + 4096,
    };
    http_resp_t resp;
    if (http_do(&req, &resp) != 0) return -1;
    int rc = -1;
    if (resp.status == 200 || resp.status == 206) {
        *out = (unsigned char *)resp.body;
        *out_len = resp.body_len;
        resp.body = NULL;
        rc = 0;
    }
    resp_free(&resp);
    return rc;
}

static int put_all(const char *rel, const unsigned char *data, size_t len) {
    http_req_t req = {
        .method = "PUT",
        .rel_path = rel,
        .body = data,
        .body_len = len,
        .want_body = 0,
    };
    http_resp_t resp;
    if (http_do(&req, &resp) != 0) return -1;
    int rc = (resp.status >= 200 && resp.status < 300) ? 0 : -1;
    if (rc != 0) logmsg("PUT %s -> %d", rel, resp.status);
    resp_free(&resp);
    return rc;
}

static int delete_path(const char *rel) {
    http_req_t req = { .method = "DELETE", .rel_path = rel, .want_body = 0 };
    http_resp_t resp;
    if (http_do(&req, &resp) != 0) return -1;
    int rc = (resp.status >= 200 && resp.status < 300) ? 0 : -1;
    resp_free(&resp);
    return rc;
}

static int mkcol(const char *rel) {
    http_req_t req = { .method = "MKCOL", .rel_path = rel, .want_body = 0 };
    http_resp_t resp;
    if (http_do(&req, &resp) != 0) return -1;
    int rc = (resp.status >= 200 && resp.status < 300) ? 0 : -1;
    if (rc != 0) logmsg("MKCOL %s -> %d", rel, resp.status);
    resp_free(&resp);
    return rc;
}

static char *make_destination(const char *dest_rel) {
    char *enc = url_encode_path(dest_rel);
    size_t n = strlen(g_wd.host) + 64 + strlen(enc);
    char *hdr = xmalloc(n);
    snprintf(hdr, n, "http%s://%s:%d%s\r\n",
             g_wd.https ? "s" : "", g_wd.host, g_wd.port, enc);
    free(enc);
    return hdr;
}

static int move_path(const char *from_rel, const char *to_rel);
static int copy_path(const char *from_rel, const char *to_rel);
static int delete_path(const char *rel);

static int move_path(const char *from_rel, const char *to_rel) {
    char *dest = make_destination(to_rel);
    char hdr[1024];
    snprintf(hdr, sizeof hdr, "Destination: %sOverwrite: T\r\n", dest);
    free(dest);
    http_req_t req = {
        .method = "MOVE", .rel_path = from_rel,
        .extra_headers = hdr, .want_body = 0,
    };
    http_resp_t resp;
    if (http_do(&req, &resp) != 0) return -1;
    if (resp.status >= 200 && resp.status < 300) { resp_free(&resp); return 0; }
    int status = resp.status;
    resp_free(&resp);
    if (status == 403 || status == 409 || status == 501 || status == 502) {
        if (copy_path(from_rel, to_rel) == 0) return delete_path(from_rel);
    }
    logmsg("MOVE %s -> %s failed (%d)", from_rel, to_rel, status);
    return -1;
}

static int copy_path(const char *from_rel, const char *to_rel) {
    char *dest = make_destination(to_rel);
    char hdr[1024];
    snprintf(hdr, sizeof hdr, "Destination: %sOverwrite: T\r\n", dest);
    free(dest);
    http_req_t req = {
        .method = "COPY", .rel_path = from_rel,
        .extra_headers = hdr, .want_body = 0,
    };
    http_resp_t resp;
    if (http_do(&req, &resp) != 0) return -1;
    int rc = (resp.status >= 200 && resp.status < 300) ? 0 : -1;
    resp_free(&resp);
    return rc;
}

/* forward decls used above */
static int copy_path(const char *from_rel, const char *to_rel);

/* ----------------------------------------------------------- caches + nodes */
typedef struct {
    uint64_t ino;
    char *path;
    int is_dir;
} node_t;

static node_t *g_nodes;
static size_t g_node_n = 0, g_node_cap = 0;
static uint64_t g_next_ino = 2;

static node_t *node_by_ino(uint64_t ino) {
    for (size_t i = 0; i < g_node_n; i++)
        if (g_nodes[i].ino == ino) return &g_nodes[i];
    return NULL;
}

static node_t *node_by_path(const char *path) {
    for (size_t i = 0; i < g_node_n; i++)
        if (!strcmp(g_nodes[i].path, path)) return &g_nodes[i];
    return NULL;
}

static node_t *node_add(const char *path, int is_dir) {
    node_t *ex = node_by_path(path);
    if (ex) { ex->is_dir = is_dir; return ex; }
    if (g_node_n == g_node_cap) {
        g_node_cap = g_node_cap ? g_node_cap * 2 : 64;
        g_nodes = xrealloc(g_nodes, g_node_cap * sizeof *g_nodes);
    }
    node_t *n = &g_nodes[g_node_n++];
    n->ino = g_next_ino++;
    n->path = xstrdup(path);
    n->is_dir = is_dir;
    return n;
}

static char *path_join2(const char *parent, const char *name) {
    size_t pl = strlen(parent), nl = strlen(name);
    char *p = xmalloc(pl + nl + 2);
    if (pl) { memcpy(p, parent, pl); p[pl] = '/'; memcpy(p + pl + 1, name, nl + 1); }
    else memcpy(p, name, nl + 1);
    return p;
}

typedef struct {
    char *path;
    dent_t *ents;
    size_t n;
    time_t expires;
} dcache_t;

static dcache_t *g_dcache;
static size_t g_dc_n = 0, g_dc_cap = 0;
static int g_cache_ttl = DEFAULT_CACHE_TTL;

static dcache_t *dcache_get(const char *path) {
    for (size_t i = 0; i < g_dc_n; i++)
        if (!strcmp(g_dcache[i].path, path))
            return (g_dcache[i].expires > time(NULL)) ? &g_dcache[i] : NULL;
    return NULL;
}

static void dcache_put(const char *path, dent_t *ents, size_t n) {
    for (size_t i = 0; i < g_dc_n; i++) {
        if (!strcmp(g_dcache[i].path, path)) {
            for (size_t j = 0; j < g_dcache[i].n; j++) free(g_dcache[i].ents[j].name);
            free(g_dcache[i].ents);
            g_dcache[i].ents = ents;
            g_dcache[i].n = n;
            g_dcache[i].expires = time(NULL) + g_cache_ttl;
            return;
        }
    }
    if (g_dc_n == g_dc_cap) {
        g_dc_cap = g_dc_cap ? g_dc_cap * 2 : 16;
        g_dcache = xrealloc(g_dcache, g_dc_cap * sizeof *g_dcache);
    }
    g_dcache[g_dc_n].path = xstrdup(path);
    g_dcache[g_dc_n].ents = ents;
    g_dcache[g_dc_n].n = n;
    g_dcache[g_dc_n].expires = time(NULL) + g_cache_ttl;
    g_dc_n++;
}

static void dcache_invalidate(const char *path) {
    for (size_t i = 0; i < g_dc_n; i++) {
        if (!strcmp(g_dcache[i].path, path)) {
            for (size_t j = 0; j < g_dcache[i].n; j++) free(g_dcache[i].ents[j].name);
            free(g_dcache[i].ents);
            free(g_dcache[i].path);
            g_dcache[i] = g_dcache[g_dc_n - 1];
            g_dc_n--;
            return;
        }
    }
}

static void dcache_invalidate_parent(const char *path) {
    char *copy = xstrdup(path);
    char *slash = strrchr(copy, '/');
    if (slash) {
        *slash = 0;
        dcache_invalidate(copy);
    }
    dcache_invalidate(path);
    free(copy);
}

static dent_t *dcache_find(dcache_t *dc, const char *name, int ci) {
    for (size_t i = 0; i < dc->n; i++)
        if (!strcmp(dc->ents[i].name, name)) return &dc->ents[i];
    if (ci) {
        for (size_t i = 0; i < dc->n; i++)
            if (!strcasecmp(dc->ents[i].name, name)) return &dc->ents[i];
    }
    return NULL;
}

static dcache_t *dcache_refresh(const char *path) {
    dent_t *ents = NULL;
    size_t n = 0;
    if (propfind_list(path, &ents, &n) != 0) return NULL;
    dcache_put(path, ents, n);
    for (size_t i = 0; i < g_dc_n; i++)
        if (!strcmp(g_dcache[i].path, path)) return &g_dcache[i];
    return NULL;
}

typedef struct {
    uint64_t ino;
    long long size;
    time_t mtime;
    time_t valid;
} facc_t;

static facc_t *g_facc;
static size_t g_fa_n = 0, g_fa_cap = 0;

static facc_t *facc_get(uint64_t ino) {
    for (size_t i = 0; i < g_fa_n; i++)
        if (g_facc[i].ino == ino) return &g_facc[i];
    return NULL;
}

static facc_t *facc_touch(uint64_t ino, long long size, time_t mtime) {
    facc_t *f = facc_get(ino);
    if (!f) {
        if (g_fa_n == g_fa_cap) {
            g_fa_cap = g_fa_cap ? g_fa_cap * 2 : 64;
            g_facc = xrealloc(g_facc, g_fa_cap * sizeof *g_facc);
        }
        f = &g_facc[g_fa_n++];
        f->ino = ino;
    }
    f->size = size;
    f->mtime = mtime;
    f->valid = time(NULL) + g_cache_ttl;
    return f;
}

static void facc_drop(uint64_t ino) {
    for (size_t i = 0; i < g_fa_n; i++) {
        if (g_facc[i].ino == ino) {
            g_facc[i] = g_facc[g_fa_n - 1];
            g_fa_n--;
            return;
        }
    }
}

typedef struct {
    uint64_t ino;
    long long off;
    unsigned char *buf;
    size_t len;
} window_t;

static window_t g_win;

static void win_drop(void) {
    free(g_win.buf);
    g_win.buf = NULL;
    g_win.len = 0;
    g_win.ino = 0;
}

typedef struct {
    uint64_t fh;
    node_t *node;
    unsigned char *buf;
    size_t len;
    int dirty;
    int writable;
} wfh_t;

static wfh_t *g_wfhs;
static size_t g_wf_n = 0, g_wf_cap = 0;
static uint64_t g_next_fh = 1;
static size_t g_max_write_file = DEFAULT_MAX_WRITE_FILE;

static wfh_t *wfh_by_fh(uint64_t fh) {
    for (size_t i = 0; i < g_wf_n; i++)
        if (g_wfhs[i].fh == fh) return &g_wfhs[i];
    return NULL;
}

static void wfh_free(wfh_t *w) {
    free(w->buf);
    w->buf = NULL;
    for (size_t i = 0; i < g_wf_n; i++) {
        if (g_wfhs[i].fh == w->fh) {
            g_wfhs[i] = g_wfhs[g_wf_n - 1];
            g_wf_n--;
            return;
        }
    }
}

static wfh_t *wfh_open(node_t *node, int writable, int truncate) {
    wfh_t *w;
    if (g_wf_n == g_wf_cap) {
        g_wf_cap = g_wf_cap ? g_wf_cap * 2 : 8;
        g_wfhs = xrealloc(g_wfhs, g_wf_cap * sizeof *g_wfhs);
    }
    w = &g_wfhs[g_wf_n++];
    memset(w, 0, sizeof *w);
    w->fh = g_next_fh++;
    w->node = node;
    w->writable = writable;
    if (writable) {
        w->len = 0;
        w->dirty = 1;
        if (!truncate) {
            long long sz = 0;
            facc_t *f = facc_get(node->ino);
            if (f) sz = f->size;
            if (sz > 0) {
                if ((size_t)sz > g_max_write_file) {
                    logmsg("file too large to open for write: %s (%lld)", node->path, sz);
                    free(w);
                    g_wf_n--;
                    return NULL;
                }
                unsigned char *data = NULL;
                size_t dlen = 0;
                if (get_range(node->path, 0, sz, &data, &dlen) != 0) {
                    free(w);
                    g_wf_n--;
                    return NULL;
                }
                w->buf = data;
                w->len = dlen;
                w->dirty = 0;
            }
        }
    }
    return w;
}

static void invalidate_for_write(node_t *node) {
    dcache_invalidate_parent(node->path);
    facc_drop(node->ino);
    if (g_win.ino == node->ino) win_drop();
}

/* ------------------------------------------------------------- fuse plumbing */
static int g_fuse_fd = -1;
static char *g_mountpoint = NULL;

static void fuse_reply(uint64_t unique, int error, const void *data, size_t len) {
    struct fuse_out_header oh;
    oh.len = (uint32_t)(sizeof oh + len);
    oh.error = error;
    oh.unique = unique;
    struct iovec iov[2];
    iov[0].iov_base = &oh;
    iov[0].iov_len = sizeof oh;
    int n = 1;
    if (data && len) {
        iov[1].iov_base = (void *)data;
        iov[1].iov_len = len;
        n = 2;
    }
    (void)writev(g_fuse_fd, iov, n);
}

static void fill_attr(struct fuse_attr *a, node_t *node, long long size) {
    memset(a, 0, sizeof *a);
    a->ino = node->ino;
    a->size = (uint64_t)(size < 0 ? 0 : size);
    a->blocks = (uint64_t)((a->size + 511) / 512);
    a->mode = node->is_dir ? (S_IFDIR | 0755) : (S_IFREG | 0666);
    a->nlink = node->is_dir ? 2 : 1;
    a->uid = 0;
    a->gid = 0;
    a->blksize = 4096;
    facc_t *f = facc_get(node->ino);
    time_t mt = f ? f->mtime : time(NULL);
    a->mtime = (uint64_t)mt;
    a->ctime = (uint64_t)mt;
    a->atime = (uint64_t)mt;
}

static int node_refresh(node_t *node, long long *size_out, time_t *mtime_out) {
    if (node->is_dir) {
        if (!dcache_get(node->path) && !dcache_refresh(node->path))
            return -EIO;
        *size_out = 0;
        *mtime_out = time(NULL);
        return 0;
    }
    facc_t *f = facc_get(node->ino);
    if (f && f->valid > time(NULL)) {
        *size_out = f->size;
        *mtime_out = f->mtime;
        return 0;
    }
    long long size = 0;
    time_t mtime = 0;
    if (propfind_self(node->path, &(int){0}, &size, &mtime) != 0) {
        if (head_self(node->path, &size, &mtime) != 0) return -EIO;
    }
    facc_touch(node->ino, size, mtime);
    *size_out = size;
    *mtime_out = mtime;
    return 0;
}

static node_t *lookup_child(node_t *dir, const char *name) {
    if (!dir->is_dir) return NULL;
    dcache_t *dc = dcache_get(dir->path);
    if (!dc) dc = dcache_refresh(dir->path);
    if (!dc) return NULL;
    dent_t *d = dcache_find(dc, name, 1);
    if (!d) return NULL;
    char *child_path = path_join2(dir->path, d->name);
    if (strcmp(d->name, name)) {
        free(child_path);
        child_path = path_join2(dir->path, name);
    }
    node_t *n = node_add(child_path, d->is_dir);
    facc_touch(n->ino, d->size, d->mtime);
    free(child_path);
    return n;
}

static void reply_entry(uint64_t unique, node_t *node) {
    long long size = 0;
    time_t mtime = 0;
    if (node_refresh(node, &size, &mtime) != 0) {
        fuse_reply(unique, -EIO, NULL, 0);
        return;
    }
    struct fuse_entry_out eo;
    memset(&eo, 0, sizeof eo);
    eo.nodeid = node->ino;
    eo.generation = 1;
    eo.entry_valid = (uint64_t)g_cache_ttl;
    eo.attr_valid = (uint64_t)g_cache_ttl;
    fill_attr(&eo.attr, node, size);
    fuse_reply(unique, 0, &eo, sizeof eo);
}

/* ------------------------------------------------------------- fuse handlers */
static void op_init(struct fuse_in_header *ih, char *payload) {
    (void)payload;
    struct fuse_init_out io;
    memset(&io, 0, sizeof io);
    io.major = FUSE_VERSION_MAJOR;
    io.minor = FUSE_VERSION_MINOR;
    io.max_readahead = MAX_WRITE;
    io.flags = 0;
    io.max_background = 16;
    io.congestion_threshold = 8;
    io.max_write = MAX_WRITE;
    io.time_gran = 1;
    fuse_reply(ih->unique, 0, &io, sizeof io);
}

static void op_lookup(struct fuse_in_header *ih, char *name) {
    node_t *dir = node_by_ino(ih->nodeid);
    if (!dir || !dir->is_dir) { fuse_reply(ih->unique, -ENOTDIR, NULL, 0); return; }
    if (!strcmp(name, ".")) { reply_entry(ih->unique, dir); return; }
    if (!strcmp(name, "..")) {
        fuse_reply(ih->unique, -ENOENT, NULL, 0);
        return;
    }
    node_t *child = lookup_child(dir, name);
    if (!child) { fuse_reply(ih->unique, -ENOENT, NULL, 0); return; }
    reply_entry(ih->unique, child);
}

static void op_getattr(struct fuse_in_header *ih, struct fuse_getattr_in *in) {
    (void)in;
    node_t *node = node_by_ino(ih->nodeid);
    if (!node) { fuse_reply(ih->unique, -ENOENT, NULL, 0); return; }
    long long size = 0;
    time_t mtime = 0;
    if (node_refresh(node, &size, &mtime) != 0) {
        fuse_reply(ih->unique, -EIO, NULL, 0);
        return;
    }
    struct fuse_attr_out ao;
    memset(&ao, 0, sizeof ao);
    ao.attr_valid = (uint64_t)g_cache_ttl;
    fill_attr(&ao.attr, node, size);
    fuse_reply(ih->unique, 0, &ao, sizeof ao);
}

static void op_setattr(struct fuse_in_header *ih, struct fuse_setattr_in *in) {
    node_t *node = node_by_ino(ih->nodeid);
    if (!node) { fuse_reply(ih->unique, -ENOENT, NULL, 0); return; }
    if ((in->valid & FATTR_SIZE) && !node->is_dir) {
        wfh_t *w = in->fh ? wfh_by_fh(in->fh) : NULL;
        if (w && w->writable) {
            size_t nsz = (size_t)in->size;
            if (nsz > w->len) {
                if (nsz > g_max_write_file) {
                    fuse_reply(ih->unique, -EFBIG, NULL, 0);
                    return;
                }
                w->buf = xrealloc(w->buf, nsz);
                memset(w->buf + w->len, 0, nsz - w->len);
            }
            w->len = nsz;
            w->dirty = 1;
        } else {
            if (in->size == 0) {
                if (put_all(node->path, (const unsigned char *)"", 0) != 0) {
                    fuse_reply(ih->unique, -EIO, NULL, 0);
                    return;
                }
            } else {
                fuse_reply(ih->unique, -EPERM, NULL, 0);
                return;
            }
        }
        invalidate_for_write(node);
    }
    long long size = 0;
    time_t mtime = 0;
    if (node_refresh(node, &size, &mtime) != 0 &&
        (in->valid & FATTR_SIZE)) {
        size = (long long)in->size;
        mtime = time(NULL);
        facc_touch(node->ino, size, mtime);
    } else if (in->valid & FATTR_SIZE) {
        size = (long long)in->size;
        facc_touch(node->ino, size, time(NULL));
    }
    struct fuse_attr_out ao;
    memset(&ao, 0, sizeof ao);
    ao.attr_valid = (uint64_t)g_cache_ttl;
    fill_attr(&ao.attr, node, size);
    fuse_reply(ih->unique, 0, &ao, sizeof ao);
}

static void op_opendir(struct fuse_in_header *ih) {
    node_t *node = node_by_ino(ih->nodeid);
    if (!node || !node->is_dir) { fuse_reply(ih->unique, -ENOTDIR, NULL, 0); return; }
    if (!dcache_get(node->path) && !dcache_refresh(node->path)) {
        fuse_reply(ih->unique, -EIO, NULL, 0);
        return;
    }
    struct fuse_open_out oo;
    memset(&oo, 0, sizeof oo);
    oo.fh = node->ino;
    fuse_reply(ih->unique, 0, &oo, sizeof oo);
}

static void op_readdir(struct fuse_in_header *ih, struct fuse_read_in *in) {
    node_t *node = node_by_ino(ih->nodeid);
    if (!node || !node->is_dir) { fuse_reply(ih->unique, -ENOTDIR, NULL, 0); return; }
    dcache_t *dc = dcache_get(node->path);
    if (!dc) dc = dcache_refresh(node->path);
    if (!dc) { fuse_reply(ih->unique, -EIO, NULL, 0); return; }
    size_t cap = in->size < 4096 ? 4096 : in->size;
    unsigned char *buf = xmalloc(cap);
    size_t used = 0;
    uint64_t next_off = 1;
    for (size_t i = 0; i < dc->n; i++) {
        if (next_off <= in->offset) { next_off = i + 2; continue; }
        size_t namelen = strlen(dc->ents[i].name);
        size_t entlen = FUSE_DIRENT_ALIGN(sizeof(struct fuse_dirent) + namelen);
        if (used + entlen > cap) break;
        struct fuse_dirent *de = (struct fuse_dirent *)(buf + used);
        memset(de, 0, entlen);
        de->ino = node->ino + 100000 + i;
        de->off = i + 2;
        de->namelen = (uint32_t)namelen;
        de->type = dc->ents[i].is_dir ? 4 : 8;
        memcpy(de->name, dc->ents[i].name, namelen);
        used += entlen;
    }
    fuse_reply(ih->unique, 0, buf, used);
    free(buf);
}

static void op_open(struct fuse_in_header *ih, struct fuse_open_in *in) {
    node_t *node = node_by_ino(ih->nodeid);
    if (!node || node->is_dir) { fuse_reply(ih->unique, -EISDIR, NULL, 0); return; }
    int writable = (in->flags & (O_WRONLY | O_RDWR)) != 0;
    int truncate = (in->flags & O_TRUNC) != 0;
    wfh_t *w = wfh_open(node, writable, truncate);
    if (!w) { fuse_reply(ih->unique, -EIO, NULL, 0); return; }
    struct fuse_open_out oo;
    memset(&oo, 0, sizeof oo);
    oo.fh = w->fh;
    fuse_reply(ih->unique, 0, &oo, sizeof oo);
}

static void op_create(struct fuse_in_header *ih, struct fuse_create_in *in,
                      char *name) {
    (void)in;
    node_t *dir = node_by_ino(ih->nodeid);
    if (!dir || !dir->is_dir) { fuse_reply(ih->unique, -ENOTDIR, NULL, 0); return; }
    char *child_path = path_join2(dir->path, name);
    if (put_all(child_path, (const unsigned char *)"", 0) != 0) {
        free(child_path);
        fuse_reply(ih->unique, -EIO, NULL, 0);
        return;
    }
    dcache_invalidate(dir->path);
    node_t *node = node_add(child_path, 0);
    facc_touch(node->ino, 0, time(NULL));
    free(child_path);
    wfh_t *w = wfh_open(node, 1, 1);
    if (!w) { fuse_reply(ih->unique, -EIO, NULL, 0); return; }
    struct {
        struct fuse_entry_out eo;
        struct fuse_open_out oo;
    } combo;
    memset(&combo, 0, sizeof combo);
    combo.eo.nodeid = node->ino;
    combo.eo.generation = 1;
    combo.eo.entry_valid = (uint64_t)g_cache_ttl;
    combo.eo.attr_valid = (uint64_t)g_cache_ttl;
    fill_attr(&combo.eo.attr, node, 0);
    combo.oo.fh = w->fh;
    fuse_reply(ih->unique, 0, &combo, sizeof combo);
}

static void op_read(struct fuse_in_header *ih, struct fuse_read_in *in) {
    node_t *node = node_by_ino(ih->nodeid);
    if (!node || node->is_dir) { fuse_reply(ih->unique, -EISDIR, NULL, 0); return; }
    wfh_t *w = in->fh ? wfh_by_fh(in->fh) : NULL;
    if (w) {
        if ((size_t)in->offset >= w->len) { fuse_reply(ih->unique, 0, NULL, 0); return; }
        size_t avail = w->len - (size_t)in->offset;
        size_t n = in->size < avail ? in->size : avail;
        fuse_reply(ih->unique, 0, w->buf + in->offset, n);
        return;
    }
    long long size = 0;
    time_t mtime = 0;
    if (node_refresh(node, &size, &mtime) != 0) {
        fuse_reply(ih->unique, -EIO, NULL, 0);
        return;
    }
    if (in->offset >= (uint64_t)size) { fuse_reply(ih->unique, 0, NULL, 0); return; }
    size_t want = in->size;
    if (in->offset + want > (uint64_t)size)
        want = (size_t)(size - (long long)in->offset);
    if (g_win.ino == node->ino && in->offset >= (uint64_t)g_win.off &&
        in->offset + want <= (uint64_t)(g_win.off + (long long)g_win.len)) {
        size_t o = (size_t)(in->offset - (uint64_t)g_win.off);
        fuse_reply(ih->unique, 0, g_win.buf + o, want);
        return;
    }
    size_t fetch = want > WINDOW_CAP ? want : WINDOW_CAP;
    if (in->offset + fetch > (uint64_t)size)
        fetch = (size_t)(size - (long long)in->offset);
    unsigned char *data = NULL;
    size_t dlen = 0;
    if (get_range(node->path, (long long)in->offset, (long long)fetch,
                  &data, &dlen) != 0) {
        fuse_reply(ih->unique, -EIO, NULL, 0);
        return;
    }
    win_drop();
    g_win.ino = node->ino;
    g_win.off = (long long)in->offset;
    g_win.buf = data;
    g_win.len = dlen;
    if (want > dlen) want = dlen;
    fuse_reply(ih->unique, 0, g_win.buf, want);
}

static void op_write(struct fuse_in_header *ih, struct fuse_write_in *in,
                     char *payload) {
    node_t *node = node_by_ino(ih->nodeid);
    if (!node || node->is_dir) { fuse_reply(ih->unique, -EISDIR, NULL, 0); return; }
    wfh_t *w = in->fh ? wfh_by_fh(in->fh) : NULL;
    if (!w || !w->writable) { fuse_reply(ih->unique, -EBADF, NULL, 0); return; }
    size_t end = (size_t)in->offset + in->size;
    if (end > g_max_write_file) { fuse_reply(ih->unique, -EFBIG, NULL, 0); return; }
    if (end > w->len) {
        w->buf = xrealloc(w->buf, end);
        if (end > w->len) memset(w->buf + w->len, 0, end - w->len);
        w->len = end;
    }
    memcpy(w->buf + in->offset, payload, in->size);
    w->dirty = 1;
    struct fuse_write_out wo;
    memset(&wo, 0, sizeof wo);
    wo.size = in->size;
    fuse_reply(ih->unique, 0, &wo, sizeof wo);
}

static int flush_handle(wfh_t *w) {
    if (!w || !w->dirty) return 0;
    if (put_all(w->node->path, w->buf, w->len) != 0) return -EIO;
    w->dirty = 0;
    invalidate_for_write(w->node);
    facc_touch(w->node->ino, (long long)w->len, time(NULL));
    return 0;
}

static void op_release(struct fuse_in_header *ih, struct fuse_release_in *in) {
    wfh_t *w = in->fh ? wfh_by_fh(in->fh) : NULL;
    if (w) {
        int rc = flush_handle(w);
        if (rc != 0) { fuse_reply(ih->unique, rc, NULL, 0); wfh_free(w); return; }
        wfh_free(w);
    }
    fuse_reply(ih->unique, 0, NULL, 0);
}

static void op_flush(struct fuse_in_header *ih, struct fuse_flush_in *in) {
    wfh_t *w = in->fh ? wfh_by_fh(in->fh) : NULL;
    fuse_reply(ih->unique, flush_handle(w), NULL, 0);
}

static void op_fsync(struct fuse_in_header *ih, struct fuse_fsync_in *in) {
    wfh_t *w = in->fh ? wfh_by_fh(in->fh) : NULL;
    fuse_reply(ih->unique, flush_handle(w), NULL, 0);
}

static void op_unlink(struct fuse_in_header *ih, char *name) {
    node_t *dir = node_by_ino(ih->nodeid);
    if (!dir) { fuse_reply(ih->unique, -ENOENT, NULL, 0); return; }
    char *child_path = path_join2(dir->path, name);
    if (delete_path(child_path) != 0) {
        free(child_path);
        fuse_reply(ih->unique, -EIO, NULL, 0);
        return;
    }
    node_t *child = node_by_path(child_path);
    if (child) facc_drop(child->ino);
    dcache_invalidate(dir->path);
    free(child_path);
    fuse_reply(ih->unique, 0, NULL, 0);
}

static void op_mkdir(struct fuse_in_header *ih, struct fuse_mkdir_in *in,
                     char *name) {
    (void)in;
    node_t *dir = node_by_ino(ih->nodeid);
    if (!dir || !dir->is_dir) { fuse_reply(ih->unique, -ENOTDIR, NULL, 0); return; }
    char *child_path = path_join2(dir->path, name);
    if (mkcol(child_path) != 0) {
        free(child_path);
        fuse_reply(ih->unique, -EIO, NULL, 0);
        return;
    }
    dcache_invalidate(dir->path);
    node_t *node = node_add(child_path, 1);
    free(child_path);
    reply_entry(ih->unique, node);
}

static void op_rmdir(struct fuse_in_header *ih, char *name) {
    node_t *dir = node_by_ino(ih->nodeid);
    if (!dir) { fuse_reply(ih->unique, -ENOENT, NULL, 0); return; }
    char *child_path = path_join2(dir->path, name);
    if (delete_path(child_path) != 0) {
        free(child_path);
        fuse_reply(ih->unique, -EIO, NULL, 0);
        return;
    }
    dcache_invalidate(dir->path);
    free(child_path);
    fuse_reply(ih->unique, 0, NULL, 0);
}

static void op_rename(struct fuse_in_header *ih, struct fuse_rename_in *in,
                      char *names) {
    node_t *olddir = node_by_ino(ih->nodeid);
    node_t *newdir = node_by_ino(in->newdir);
    if (!olddir || !newdir) { fuse_reply(ih->unique, -ENOENT, NULL, 0); return; }
    char *oldname = names;
    char *newname = names + strlen(names) + 1;
    char *from = path_join2(olddir->path, oldname);
    char *to = path_join2(newdir->path, newname);
    if (move_path(from, to) != 0) {
        free(from);
        free(to);
        fuse_reply(ih->unique, -EIO, NULL, 0);
        return;
    }
    node_t *mn = node_by_path(from);
    if (mn) {
        free(mn->path);
        mn->path = xstrdup(to);
    }
    facc_drop(mn ? mn->ino : 0);
    dcache_invalidate(olddir->path);
    dcache_invalidate(newdir->path);
    free(from);
    free(to);
    fuse_reply(ih->unique, 0, NULL, 0);
}

static void op_statfs(struct fuse_in_header *ih) {
    struct fuse_kstatfs ks;
    memset(&ks, 0, sizeof ks);
    ks.bsize = 4096;
    ks.frsize = 4096;
    ks.blocks = 16777216;
    ks.bfree = 16777216;
    ks.bavail = 16777216;
    ks.files = 4194304;
    ks.ffree = 4194304;
    ks.namelen = 255;
    fuse_reply(ih->unique, 0, &ks, sizeof ks);
}

static void dispatch(uint64_t unique, uint32_t opcode, uint64_t nodeid,
                     char *payload) {
    struct fuse_in_header fake;
    fake.len = 0;
    fake.opcode = opcode;
    fake.unique = unique;
    fake.nodeid = nodeid;
    switch (opcode) {
    case FUSE_LOOKUP: op_lookup(&fake, payload); break;
    case FUSE_GETATTR: op_getattr(&fake, (struct fuse_getattr_in *)payload); break;
    case FUSE_SETATTR: op_setattr(&fake, (struct fuse_setattr_in *)payload); break;
    case FUSE_OPENDIR: op_opendir(&fake); break;
    case FUSE_READDIR: op_readdir(&fake, (struct fuse_read_in *)payload); break;
    case FUSE_RELEASEDIR: fuse_reply(unique, 0, NULL, 0); break;
    case FUSE_OPEN: op_open(&fake, (struct fuse_open_in *)payload); break;
    case FUSE_READ: op_read(&fake, (struct fuse_read_in *)payload); break;
    case FUSE_WRITE: {
        struct fuse_write_in *in = (struct fuse_write_in *)payload;
        op_write(&fake, in, payload + sizeof(struct fuse_write_in));
        break;
    }
    case FUSE_RELEASE: op_release(&fake, (struct fuse_release_in *)payload); break;
    case FUSE_FLUSH: op_flush(&fake, (struct fuse_flush_in *)payload); break;
    case FUSE_FSYNC: op_fsync(&fake, (struct fuse_fsync_in *)payload); break;
    case FUSE_CREATE: {
        struct fuse_create_in *in = (struct fuse_create_in *)payload;
        op_create(&fake, in, payload + sizeof(struct fuse_create_in));
        break;
    }
    case FUSE_UNLINK: op_unlink(&fake, payload); break;
    case FUSE_MKDIR: {
        struct fuse_mkdir_in *in = (struct fuse_mkdir_in *)payload;
        op_mkdir(&fake, in, payload + sizeof(struct fuse_mkdir_in));
        break;
    }
    case FUSE_RMDIR: op_rmdir(&fake, payload); break;
    case FUSE_RENAME: {
        struct fuse_rename_in *in = (struct fuse_rename_in *)payload;
        op_rename(&fake, in, payload + sizeof(struct fuse_rename_in));
        break;
    }
    case FUSE_STATFS: op_statfs(&fake); break;
    case FUSE_FORGET:
    case FUSE_BATCH_FORGET:
        break;
    case FUSE_GETXATTR:
    case FUSE_SETXATTR:
    case FUSE_LISTXATTR:
        fuse_reply(unique, -ENOSYS, NULL, 0);
        break;
    case FUSE_ACCESS:
        fuse_reply(unique, 0, NULL, 0);
        break;
    case FUSE_FSYNCDIR:
        fuse_reply(unique, 0, NULL, 0);
        break;
    case FUSE_INTERRUPT:
        fuse_reply(unique, -EINTR, NULL, 0);
        break;
    default:
        fuse_reply(unique, -ENOSYS, NULL, 0);
        break;
    }
}

/* ---------------------------------------------------------------- selftest */
static int selftest(void) {
    int fails = 0;
    char *enc = url_encode_path("/c/My Drive (1)/file #1.mp4");
    if (strcmp(enc, "/c/My%20Drive%20%281%29/file%20%231.mp4")) {
        fprintf(stderr, "selftest: url_encode failed: %s\n", enc);
        fails++;
    }
    free(enc);
    char *dec = url_decode("My%20Drive%3AFoo%2Fbar");
    if (strcmp(dec, "My Drive:Foo/bar")) {
        fprintf(stderr, "selftest: url_decode failed: %s\n", dec);
        fails++;
    }
    free(dec);
    char *unc = xml_unescape("a&amp;b&lt;c&gt;d&quot;e&apos;f&#65;");
    if (strcmp(unc, "a&b<c>d\"e'fA")) {
        fprintf(stderr, "selftest: xml_unescape failed: %s\n", unc);
        fails++;
    }
    free(unc);
    {
        char *b = b64_encode((const unsigned char *)"user:pass", 9);
        if (strcmp(b, "dXNlcjpwYXNz")) {
            fprintf(stderr, "selftest: base64 failed: %s\n", b);
            fails++;
        }
        free(b);
    }
    {
        const char *sample =
            "<?xml version=\"1.0\"?>"
            "<D:multistatus xmlns:D=\"DAV:\">"
            "<D:response><D:href>/c/</D:href><D:propstat><D:prop>"
            "<D:resourcetype><D:collection/></D:resourcetype></D:prop>"
            "</D:propstat></D:response>"
            "<D:response><D:href>/c/Sub%20Dir/</D:href><D:propstat><D:prop>"
            "<D:resourcetype><D:collection/></D:resourcetype>"
            "</D:prop></D:propstat></D:response>"
            "<D:response><D:href>/c/a%26b.txt</D:href><D:propstat><D:prop>"
            "<D:getcontentlength>1234</D:getcontentlength>"
            "<D:getlastmodified>Mon, 06 Jan 2025 12:00:00 GMT</D:getlastmodified>"
            "</D:prop></D:propstat></D:response>"
            "</D:multistatus>";
        size_t n = 0;
        char *work = xstrdup(sample);
        const char *p = work;
        char href[512];
        int first = 1;
        while ((p = tag_body(p, "href", href, sizeof href)) != NULL) {
            if (first) { first = 0; continue; }
            dent_t d;
            memset(&d, 0, sizeof d);
            char *full = xml_unescape(href);
            d.name = href_to_name(full);
            free(full);
            /* bound the scan to this <D:response> so we don't pick up
               the next entry's getcontentlength */
            const char *resp_end = p;
            const char *re = p;
            while ((re = strchr(re, '<')) != NULL) {
                if (re[1] == '/') {
                    const char *nm = xml_bare_name(re);
                    if (nm && !strncasecmp(nm, "response", 8) && nm[8] == '>') {
                        resp_end = re;
                        break;
                    }
                }
                re++;
            }
            size_t span = (size_t)(resp_end - p);
            char chunk[1024];
            if (span >= sizeof chunk) span = sizeof chunk - 1;
            memcpy(chunk, p, span);
            chunk[span] = 0;
            char tmp[64];
            if (tag_body(chunk, "getcontentlength", tmp, sizeof tmp))
                d.size = atoll(tmp);
            if (n == 0) {
                if (strcmp(d.name, "Sub Dir") || d.size != 0) {
                    fprintf(stderr, "selftest: entry0 mismatch (%s, %lld)\n",
                            d.name, d.size);
                    fails++;
                }
            } else if (n == 1) {
                if (strcmp(d.name, "a&b.txt") || d.size != 1234) {
                    fprintf(stderr, "selftest: entry1 mismatch (%s, %lld)\n",
                            d.name, d.size);
                    fails++;
                }
            }
            free(d.name);
            n++;
        }
        free(work);
        if (n != 2) { fprintf(stderr, "selftest: expected 2 entries, got %zu\n", n); fails++; }
    }
    {
        time_t t = parse_http_date("Mon, 06 Jan 2025 12:00:00 GMT");
        struct tm tmv;
        gmtime_r(&t, &tmv);
        if (tmv.tm_year != 125 || tmv.tm_mon != 0 || tmv.tm_mday != 6 ||
            tmv.tm_hour != 12) {
            fprintf(stderr, "selftest: http date parse failed\n");
            fails++;
        }
    }
    if (fails == 0) printf("selftest: all passed\n");
    return fails == 0 ? 0 : 1;
}

/* -------------------------------------------------------------------- main */
static void usage(void) {
    printf("webdavfs " VERSION " - full WebDAV client FUSE filesystem\n");
    printf("Usage: webdavfs <webdav-url> <mountpoint> [-o options] [-d]\n");
    printf("       webdavfs --selftest | --version | --help\n");
    printf("Options (-o comma separated):\n");
    printf("  user=NAME pass=PWD     HTTP Basic authentication\n");
    printf("  ssl_verify=0|1         verify HTTPS certificates (default 0)\n");
    printf("  ca_path=PATH           CA bundle for ssl_verify=1\n");
    printf("  cache_ttl=SEC          directory/attr cache TTL (default %d)\n",
           DEFAULT_CACHE_TTL);
    printf("  max_write_file=BYTES   buffered write cap (default %u)\n",
           DEFAULT_MAX_WRITE_FILE);
    printf("  logfile=PATH           append logs to file\n");
    printf("  pidfile=PATH           write pid file\n");
    printf("  allow_other context=.. passed to the FUSE mount\n");
    printf("  verbose                verbose request logging\n");
}

static void apply_opt(const char *opt) {
    if (!strcmp(opt, "allow_other") || !strcmp(opt, "default_permissions") ||
        !strncmp(opt, "context=", 8) || !strncmp(opt, "fsname=", 7))
        return;
    if (!strcmp(opt, "verbose")) { g_verbose = 1; return; }
    if (!strncmp(opt, "user=", 5)) { g_wd.user = xstrdup(opt + 5); return; }
    if (!strncmp(opt, "pass=", 5)) { g_wd.pass = xstrdup(opt + 5); return; }
    if (!strncmp(opt, "ssl_verify=", 11)) { g_ssl_verify = atoi(opt + 11); return; }
    if (!strncmp(opt, "ca_path=", 8)) { g_ca_path = xstrdup(opt + 8); return; }
    if (!strncmp(opt, "cache_ttl=", 10)) {
        int v = atoi(opt + 10);
        if (v > 0) g_cache_ttl = v;
        return;
    }
    if (!strncmp(opt, "max_write_file=", 15)) {
        long long v = atoll(opt + 15);
        if (v > 0) g_max_write_file = (size_t)v;
        return;
    }
    if (!strncmp(opt, "logfile=", 8)) {
        g_logf = fopen(opt + 8, "a");
        return;
    }
    if (!strncmp(opt, "pidfile=", 8)) {
        FILE *f = fopen(opt + 8, "w");
        if (f) { fprintf(f, "%d\n", (int)getpid()); fclose(f); }
        return;
    }
    logmsg("ignoring unknown option: %s", opt);
}

int main(int argc, char **argv) {
    const char *url = NULL, *mountpoint = NULL, *fuse_opts_extra = NULL;
    int daemonize = 0, foreground = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--version") || !strcmp(argv[i], "-V")) {
            printf("webdavfs %s\n", VERSION);
            return 0;
        }
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage();
            return 0;
        }
        if (!strcmp(argv[i], "--selftest")) return selftest();
        if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--daemon")) { daemonize = 1; continue; }
        if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--foreground")) { foreground = 1; continue; }
        if (!strcmp(argv[i], "-o") && i + 1 < argc) { fuse_opts_extra = argv[++i]; continue; }
        if (!url) { url = argv[i]; continue; }
        if (!mountpoint) { mountpoint = argv[i]; continue; }
    }
    if (!url || !mountpoint) {
        fprintf(stderr, "webdavfs: missing <url> and/or <mountpoint>\n");
        usage();
        return 2;
    }
    if (parse_webdav_url(url) != 0) return 2;

    char opts_copy[1024];
    opts_copy[0] = 0;
    if (fuse_opts_extra) {
        snprintf(opts_copy, sizeof opts_copy, "%s", fuse_opts_extra);
        char *save = NULL;
        for (char *tok = strtok_r(opts_copy, ",", &save); tok;
             tok = strtok_r(NULL, ",", &save))
            apply_opt(tok);
    }
    if (daemonize && !foreground) {
        if (fork() > 0) exit(0);
        setsid();
        if (fork() > 0) exit(0);
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, 0);
            if (!g_logf) dup2(devnull, 2);
            if (devnull > 2) close(devnull);
        }
    }
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    struct stat st;
    if (stat(mountpoint, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "webdavfs: mountpoint is not a directory: %s\n", mountpoint);
        return 2;
    }

    g_fuse_fd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    if (g_fuse_fd < 0) {
        fprintf(stderr, "webdavfs: cannot open /dev/fuse: %s\n", strerror(errno));
        return 1;
    }
    char mopts[1024];
    snprintf(mopts, sizeof mopts,
             "fd=%d,rootmode=40000,user_id=%d,group_id=%d,allow_other",
             g_fuse_fd, (int)getuid(), (int)getgid());
    if (fuse_opts_extra && *fuse_opts_extra) {
        if (strlen(mopts) + strlen(fuse_opts_extra) + 2 < sizeof mopts) {
            strcat(mopts, ",");
            strcat(mopts, fuse_opts_extra);
        }
    }
    if (mount("webdavfs", mountpoint, "fuse", MS_NOSUID | MS_NODEV, mopts) != 0) {
        fprintf(stderr, "webdavfs: mount failed: %s\n", strerror(errno));
        close(g_fuse_fd);
        return 1;
    }
    g_mountpoint = xstrdup(mountpoint);
    logmsg("mounted %s at %s (%s)", url, mountpoint, VERSION);

    unsigned char *buf = xmalloc(140000);
    while (!g_stop) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(g_fuse_fd, &rfds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int sel = select(g_fuse_fd + 1, &rfds, NULL, NULL, &tv);
        if (sel <= 0) continue;
        ssize_t n = read(g_fuse_fd, buf, 140000);
        if (n <= 0) {
            if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            break;
        }
        if ((size_t)n < sizeof(struct fuse_in_header)) continue;
        struct fuse_in_header *ih = (struct fuse_in_header *)buf;
        if (ih->opcode == FUSE_INIT) {
            op_init(ih, (char *)(ih + 1));
            continue;
        }
        char *payload = (char *)(ih + 1);
        dispatch(ih->unique, ih->opcode, ih->nodeid, payload);
    }
    logmsg("shutting down");
    umount2(g_mountpoint, MNT_DETACH);
    close(g_fuse_fd);
    win_drop();
    free(buf);
    if (g_logf) fclose(g_logf);
    return 0;
}
