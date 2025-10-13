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
import com.sforce.oauth.util.OAuthUtil;
import com.sforce.ws.ConnectionException;
import com.sforce.ws.ConnectorConfig;
import com.sforce.ws.transport.Transport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Implements the OAuth 2.0 Client Credentials Flow for authentication. It exchanges the client's ID and secret directly 
 * for an access token at the authorization server's token endpoint.
 */
public class ClientCredentialsFlow implements OAuthFlow {

    private static final String GRANT_TYPE = "client_credentials";
    private static final String AUTHORIZATION_HEADER = "Authorization";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String ACCEPT_HEADER = "Accept";
    private static final String CONTENT_TYPE_HEADER = "Content-Type";

    static {
        MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    @Override
    public OAuthTokenResponse getToken(ConnectorConfig config) throws OAuthException, ConnectionException {
        if (!isConfigValid(config)) {
            throw new OAuthException("Invalid OAuth configuration: missing required parameters (client_id, client_secret, or token_endpoint)");
        }
        try {
            final Map<String, String> requestHeaders = createHeaders(config);
            final String requestBody = createRequestBody(config);
            final String tokenEndpoint = config.getTokenEndpoint();
            return exchangeCredentialsForToken(config, tokenEndpoint, requestHeaders, requestBody);
        } catch (OAuthException ex) {
            throw ex;
        } catch (IOException ex) {
            throw new ConnectionException("Error establishing token request connection with error", ex);
        } catch (Exception ex) {
            throw new ConnectionException("An unexpected error occurred during the OAuth flow", ex);
        }
    }

    /**
     * Checks if the required client credentials and token endpoint are present and non-empty.
     *
     * @param config The connector configuration.
     * @return {@code true} if all required configuration parameters are valid; {@code false} otherwise.
     */
    private boolean isConfigValid(ConnectorConfig config) {
        if (config == null) {
            return false;
        }

        String clientId = config.getClientId();
        String clientSecret = config.getClientSecret();
        String tokenEndpoint = config.getTokenEndpoint();

        return clientId != null && !clientId.trim().isEmpty() &&
                clientSecret != null && !clientSecret.trim().isEmpty() &&
                tokenEndpoint != null && !tokenEndpoint.trim().isEmpty();
    }

    /**
     * Builds the necessary HTTP request headers.
     *
     * @param config The connector configuration.
     * @return A map of headers, including Content-Type, Accept, and Basic Authorization.
     */
    private Map<String, String> createHeaders(ConnectorConfig config) {
        HashMap<String, String> requestHeaders = new java.util.HashMap<>();
        requestHeaders.put(CONTENT_TYPE_HEADER, "application/x-www-form-urlencoded");
        requestHeaders.put(ACCEPT_HEADER, "application/json");
        requestHeaders.put(AUTHORIZATION_HEADER, OAuthUtil.buildBasicAuthHeader(config.getClientId(), config.getClientSecret()));
        return requestHeaders;
    }

    /**
     * Builds the request body containing the {@code grant_type}.
     *
     * @param config The connector configuration (used for potential future scope addition).
     * @return The URL-encoded request body string.
     */
    private String createRequestBody(ConnectorConfig config) {
        return "grant_type=" + GRANT_TYPE;
    }

    /**
     * Executes the token exchange request using the provided transport and parameters.
     *
     * @param config         The connector configuration.
     * @param tokenEndpoint  The token endpoint URL.
     * @param requestHeaders Headers including Basic Auth credentials.
     * @param requestBody    The request body containing the grant type.
     * @return The successful token response.
     * @throws OAuthException      If the server returns an error response.
     * @throws ConnectionException If a transport-level error occurs.
     * @throws IOException         If an I/O error occurs during data transfer.
     */
    private OAuthTokenResponse exchangeCredentialsForToken(ConnectorConfig config, String tokenEndpoint, Map<String, String> requestHeaders, String requestBody) throws OAuthException, ConnectionException, IOException {
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
}
