#ifndef CALLBACKS_HH
#define CALLBACKS_HH

#include "cryptography/types.hh"
#include <string>

typedef void (*OnMessageReceivedCallback)(const BYTE *payload, SIZE size, const CHAR *sessionId, const CHAR *fromAddress, const CHAR *toAddress);
typedef void (*OnNewSessionSetCallback)(const CHAR *sessionId, const BYTE *sessionKey, const SIZE sessionKeySize, const CHAR *fromAddress);
// typedef void (*OnForwardFailedCallback)(const BYTE *payload, SIZE size, const CHAR *sessionId, const CHAR *fromAddress, const CHAR *toAddress);
typedef void (*OnSessionClearedCallback)(const CHAR *sessionId, const CHAR *fromAddress);

#endif
