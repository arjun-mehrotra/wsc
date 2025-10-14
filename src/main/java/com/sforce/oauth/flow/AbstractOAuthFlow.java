/*
 * Copyright (c) 2017, salesforce.com, inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *    Redistributions of source code must retain the above copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 *    Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
 *    the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 *    Neither the name of salesforce.com, inc. nor the names of its contributors may be used to endorse or
 *    promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package com.sforce.oauth.flow;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sforce.oauth.api.OAuthFlow;
import com.sforce.oauth.exception.OAuthException;
import com.sforce.oauth.model.OAuthErrorResponse;
import com.sforce.oauth.model.OAuthTokenResponse;
import com.sforce.ws.ConnectionException;
import com.sforce.ws.ConnectorConfig;
import com.sforce.ws.transport.Transport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public abstract class AbstractOAuthFlow implements OAuthFlow {

    protected static final String ACCEPT_HEADER = "Accept";
    protected static final String AUTHORIZATION_HEADER = "Authorization";
    protected static final String CONTENT_TYPE_HEADER = "Content-Type";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    static {
        MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    /**
     * Executes the OAuth 2.0 token exchange request. This method handles sending the request, processing the response,
     * and handling both success and error scenarios.
     *
     * @param config         The connector configuration containing OAuth settings
     * @param tokenEndpoint  The OAuth 2.0 token endpoint URL
     * @param requestHeaders HTTP headers for the request
     * @param requestBody    The URL-encoded request body
     * @return OAuthTokenResponse containing the access token and related OAuth information
     * @throws OAuthException      If the server returns an OAuth error response
     *                             (e.g., invalid_client, invalid_grant, unsupported_grant_type)
     * @throws ConnectionException If a network or transport-level error occurs during the request
     * @throws IOException         If an I/O error occurs during data transfer or response processing
     */
    protected OAuthTokenResponse executeTokenRequest(
            final ConnectorConfig config,
            final String tokenEndpoint,
            final Map<String, String> requestHeaders,
            final String requestBody) throws OAuthException, ConnectionException, IOException {

        Transport transport = config.createTransport();

        try (OutputStream out = transport.connect(tokenEndpoint, (HashMap<String, String>) requestHeaders, false)) {
            out.write(requestBody.getBytes(StandardCharsets.UTF_8));
            out.flush();

            try (InputStream in = transport.getContent()) {
                if (transport.isSuccessful()) {
                    return MAPPER.readValue(in, OAuthTokenResponse.class);
                } else {
                    OAuthErrorResponse errorResponse = MAPPER.readValue(in, OAuthErrorResponse.class);
                    throw new OAuthException(errorResponse.getError(), errorResponse.getErrorDescription());
                }
            }
        }
    }

    /**
     * Checks if the required configuration parameters for the specific OAuth flow are present and valid.
     *
     * @param config The connector configuration.
     * @return {@code true} if all required parameters are valid; {@code false} otherwise.
     */
    protected abstract boolean isConfigValid(ConnectorConfig config);

    /**
     * Creates the URL-encoded request body containing flow-specific parameters.
     *
     * @param config The connector configuration.
     * @return The complete URL-encoded request body string.
     */
    protected abstract String createRequestBody(ConnectorConfig config);

    /**
     * Creates the necessary HTTP request headers, including standard headers and any flow-specific authentication header.
     *
     * @param config The connector configuration.
     * @return A map of HTTP headers required for the token request.
     */
    protected abstract Map<String, String> createHeaders(ConnectorConfig config);
}
