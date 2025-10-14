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

import com.sforce.oauth.exception.OAuthException;
import com.sforce.oauth.model.OAuthTokenResponse;
import com.sforce.ws.ConnectionException;
import com.sforce.ws.ConnectorConfig;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Implements the OAuth 2.0 Refresh Token Flow for authentication. It exchanges a refresh token
 * for a new access token at the authorization server's token endpoint.
 */
public class RefreshTokenFlow extends AbstractOAuthFlow {

    private static final String GRANT_TYPE = "refresh_token";

    @Override
    public OAuthTokenResponse getToken(ConnectorConfig config) throws OAuthException, ConnectionException {
        if (!isConfigValid(config)) {
            throw new OAuthException("Invalid OAuth configuration: missing required parameters (client_id, token_endpoint, or refresh_token)");
        }

        try {
            final Map<String, String> requestHeaders = createHeaders(config);
            final String requestBody = createRequestBody(config);
            final String tokenEndpoint = config.getTokenEndpoint();
            return executeTokenRequest(config, tokenEndpoint, requestHeaders, requestBody);
        } catch (OAuthException ex) {
            throw ex;
        } catch (IOException ex) {
            throw new ConnectionException("Error establishing token request connection with error", ex);
        } catch (Exception ex) {
            throw new ConnectionException("An unexpected error occurred during the OAuth refresh token flow", ex);
        }
    }

    @Override
    protected boolean isConfigValid(ConnectorConfig config) {
        if (config == null) {
            return false;
        }

        String clientId = config.getClientId();
        String tokenEndpoint = config.getTokenEndpoint();
        String refreshToken = config.getRefreshToken();

        return clientId != null && !clientId.trim().isEmpty() &&
                tokenEndpoint != null && !tokenEndpoint.trim().isEmpty() &&
                refreshToken != null && !refreshToken.trim().isEmpty();
    }

    @Override
    protected String createRequestBody(ConnectorConfig config) {
        StringBuilder body = new StringBuilder();

        body.append("grant_type=").append(GRANT_TYPE);
        body.append("&refresh_token=").append(config.getRefreshToken());
        body.append("&client_id=").append(config.getClientId());

        String clientSecret = config.getClientSecret();
        if (clientSecret != null && !clientSecret.trim().isEmpty()) {
            body.append("&client_secret=").append(clientSecret);
        }
        return body.toString();
    }

    @Override
    protected Map<String, String> createHeaders(ConnectorConfig config) {
        Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put(CONTENT_TYPE_HEADER, "application/x-www-form-urlencoded");
        requestHeaders.put(ACCEPT_HEADER, "application/json");
        return requestHeaders;
    }
}
