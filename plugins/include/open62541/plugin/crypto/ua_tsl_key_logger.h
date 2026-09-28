#ifndef UA_TSL_KEY_LOGGER
#define UA_TSL_KEY_LOGGER

#include <open62541/client.h>
#include <open62541/server.h>

_UA_BEGIN_DECLS
UA_StatusCode UA_EXPORT
UA_ClientConfig_setFileKeyLogger(UA_ClientConfig* config, char* keyFile);
UA_StatusCode UA_EXPORT
UA_ServerConfig_setFileKeyLogger(UA_ServerConfig* config, char* keyFile);
_UA_END_DECLS

#endif // !UA_TSL_KEY_LOGGER
