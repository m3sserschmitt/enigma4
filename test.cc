#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include "tls_socket.hh"
#include <iostream>

using namespace std;

SSL *ssl;
// int sock;

int RecvPacket()
{
    int len = 100;
    char buf[1000000];
    do
    {
        len = SSL_read(ssl, buf, 100);
        buf[len] = 0;
        printf("%s\n", buf);
        //        fprintf(fp, "%s",buf);
    } while (len > 0);
    if (len < 0)
    {
        int err = SSL_get_error(ssl, len);
        if (err == SSL_ERROR_WANT_READ)
            return 0;
        if (err == SSL_ERROR_WANT_WRITE)
            return 0;
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
            return -1;
    }
}

int SendPacket(const char *buf)
{
    int len = SSL_write(ssl, buf, strlen(buf));
    if (len < 0)
    {
        int err = SSL_get_error(ssl, len);
        switch (err)
        {
        case SSL_ERROR_WANT_WRITE:
            return 0;
        case SSL_ERROR_WANT_READ:
            return 0;
        case SSL_ERROR_ZERO_RETURN:
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
        default:
            return -1;
        }
    }
}

void log_ssl()
{
    int err;
    while (err = ERR_get_error())
    {
        char *str = ERR_error_string(err, 0);
        if (!str)
            return;
        printf(str);
        printf("\n");
        fflush(stdout);
    }
}

// int main(int argc, char *argv[])
// {
//     int s;
//     s = socket(AF_INET, SOCK_STREAM, 0);
//     if (s < 0) {
//         printf("Error creating socket.\n");
//         return -1;
//     }
//     struct sockaddr_in sa;
//     memset (&sa, 0, sizeof(sa));
//     sa.sin_family      = AF_INET;
//     sa.sin_addr.s_addr = inet_addr("172.217.18.99"); // address of google.ru
//     sa.sin_port        = htons (443);
//     socklen_t socklen = sizeof(sa);
//     if (connect(s, (struct sockaddr *)&sa, socklen)) {
//         printf("Error connecting to server.\n");
//         return -1;
//     }
//     // SSL_library_init();
//     // SSLeay_add_ssl_algorithms();
//     // SSL_load_error_strings();
//     const SSL_METHOD *meth = TLS_client_method();
//     SSL_CTX *ctx = SSL_CTX_new (meth);
//     ssl = SSL_new (ctx);
//     if (!ssl) {
//         printf("Error creating SSL.\n");
//         log_ssl();
//         return -1;
//     }
//     // sock = SSL_get_fd(ssl);
//     SSL_set_fd(ssl, s);
//     int err = SSL_connect(ssl);
//     if (err <= 0) {
//         printf("Error creating SSL connection.  err=%x\n", err);
//         log_ssl();
//         fflush(stdout);
//         return -1;
//     }
//     printf ("SSL connection using %s\n", SSL_get_cipher (ssl));

//     char *request = "GET https://about.google/intl/en/ HTTP/1.1\r\n\r\n";
//     SendPacket(request);
//     RecvPacket();
//     return 0;
// }

int main()
{
    TLSSocket s("google.ro", "443");
    cout << s.get_cipher() << "\n";
}