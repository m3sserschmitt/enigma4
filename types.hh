#ifndef _TYPES_HH
#define _TYPES_HH

#include <cryptography/types.hh>
#include "osocket.hh"

typedef struct
{
    // int clientsock;
    OSocket *sock;
    AES_CRYPTO aesctx;
    RSA_CRYPTO rsactx;
    BYTES keydigest;

} connection_t;

#endif
