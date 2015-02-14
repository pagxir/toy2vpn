#ifndef _PINGLE_H_
#define _PINGLE_H_

#ifdef __cplusplus
extern "C" {
#endif

int pingle_get_configure(int tunnel, char *buf, size_t count);
int pingle_set_cookies(const char *cookies);
int pingle_set_session(const char *session);
int pingle_set_secret(const char *secret);
int pingle_set_server(const void *server, size_t len);

int pingle_do_loop(int tunnel, int tunfd);
int pingle_do_handshake(int tunnel);
int pingle_set_dnsmode(int on);

int pingle_open(void);

#ifdef __cplusplus
};
#endif

#endif

