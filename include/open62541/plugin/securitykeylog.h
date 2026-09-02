/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) Sören Krecker
 */

#ifndef UA_PLUGIN_KEY_LOG_H_
#define UA_PLUGIN_KEY_LOG_H_

#include <open62541/config.h>
#include <open62541/types.h>
#include <open62541/types_generated.h>

typedef struct UA_SecureChannelKeyLogger {
    void (*localLogger)(UA_ChannelSecurityToken token, const UA_ByteString key, UA_ByteString iv, void* keyLoggerContext);
    void (*remoteLogger)(UA_ChannelSecurityToken token, const UA_ByteString key, UA_ByteString iv, void* keyLoggerContext);
    void (*deleter)(void* keyLoggerContext);
    void* keyLoggerContext;
} UA_SecureChannelKeyLogger;

#endif