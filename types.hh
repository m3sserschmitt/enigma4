#ifndef _TYPES_HH
#define _TYPES_HH

#include <cryptography/types.hh>
#include "socket.hh"

typedef struct
{
    // int clientsock;
    Socket *sock;
    AES_CRYPTO aesctx;
    RSA_CRYPTO rsactx;
    BYTES keydigest;

} connection_t;

#endif
