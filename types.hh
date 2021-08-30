#ifndef _TYPES_HH
#define _TYPES_HH

#include <cryptography/types.hh>

typedef struct
{
    int clientsock;
    AES_CRYPTO aesctx;
    RSA_CRYPTO rsactx;
    BYTES keydigest;

} connection_t;

#endif
