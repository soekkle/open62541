/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2026 (c) Sören Krecker
 */

#include <open62541/plugin/crypto/ua_tsl_key_logger.h>
#include <open62541/plugin/securitykeylog.h>

#include <stdio.h>

static void keyLogger(UA_ChannelSecurityToken token, const UA_ByteString key, UA_ByteString iv, void* keyLoggerContext, const char* source)
{
	fprintf(keyLoggerContext, "%s:iv:%u:%u:", source,token.channelId,token.tokenId);
	for (int i = 0; i < iv.length; ++i)
		fprintf(keyLoggerContext, "%X", iv.data[i]);
	fprintf(keyLoggerContext, "\n%s:key:%u:%u:", source, token.channelId, token.tokenId);
	for (int i = 0; i < key.length; ++i)
		fprintf(keyLoggerContext, "%X", key.data[i]);
	fprintf(keyLoggerContext, "\n");
	fflush(keyLoggerContext);
}

static void serverKeyLogger(UA_ChannelSecurityToken token, const UA_ByteString key, UA_ByteString iv, void* keyLoggerContext)
{
	const static char* source = "server";
	keyLogger(token, key, iv, keyLoggerContext, source);
};

static void clientKeyLogger(UA_ChannelSecurityToken token, const UA_ByteString key, UA_ByteString iv, void* keyLoggerContext) {
	const static char* source = "client";
	keyLogger(token, key, iv, keyLoggerContext, source);
};

static void closeKeyLogger(void** keyLoggerContext)
{
	fclose(*keyLoggerContext);
	*keyLoggerContext = NULL;
}

UA_StatusCode UA_EXPORT
UA_ClientConfig_setFileKeyLogger(UA_ClientConfig* config, char* keyFile) {
	config->keyLogger.localLogger = clientKeyLogger;
	config->keyLogger.remoteLogger = serverKeyLogger;
	config->keyLogger.keyLoggerContext = fopen(keyFile, "a");
	config->keyLogger.deleter = closeKeyLogger;
}
UA_StatusCode UA_EXPORT
UA_ServerConfig_setFileKeyLogger(UA_ServerConfig* config, char* keyFile) {
	config->keyLogger.localLogger = serverKeyLogger;
	config->keyLogger.remoteLogger = clientKeyLogger;
	config->keyLogger.keyLoggerContext = fopen(keyFile, "a");
	config->keyLogger.deleter = closeKeyLogger;
}