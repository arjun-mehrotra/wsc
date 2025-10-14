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
import org.junit.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class RefreshTokenFlowTest extends AbstractOAuthFlowTestBase {

    private static final String REFRESH_TOKEN = "test_refresh_token_12345";
    private RefreshTokenFlow flowSpy;

    @Override
    protected void setUpFlows() throws OAuthException, IOException, ConnectionException {
        flow = new RefreshTokenFlow();
        flowSpy = spy(new RefreshTokenFlow());

        when(mockConfig.getRefreshToken()).thenReturn(REFRESH_TOKEN);
        when(mockConfig.getClientSecret()).thenReturn(null);

        doReturn(mock(OAuthTokenResponse.class))
                .when(flowSpy).executeTokenRequest(
                        any(ConnectorConfig.class), any(String.class), any(Map.class), any(String.class));
    }

    @Test
    public void test_isConfigValid_NullRefreshToken_ReturnsFalse() {
        when(mockConfig.getRefreshToken()).thenReturn(null);
        assertFalse("Invalid refresh token found in configuration", flow.isConfigValid(mockConfig));
    }

    @Test
    public void test_isConfigValid_NullClientId_ReturnsFalse() {
        when(mockConfig.getClientId()).thenReturn(null);
        assertFalse("Invalid client id found in configuration", flow.isConfigValid(mockConfig));
    }

    @Test
    public void test_isConfigValid_NullTokenEndpoint_ReturnsFalse() {
        when(mockConfig.getTokenEndpoint()).thenReturn(null);
        assertFalse("Invalid token endpoint found in configuration", flow.isConfigValid(mockConfig));
    }

    @Test
    public void test_createRequestBody_WithoutClientSecret() {
        String requestBody = flow.createRequestBody(mockConfig);

        assertTrue("Request body must contain grant type",
                requestBody.contains("grant_type=refresh_token"));
        assertTrue("Request body must contain refresh_token",
                requestBody.contains("&refresh_token=" + REFRESH_TOKEN));
        assertTrue("Request body must contain client_id",
                requestBody.contains("&client_id=" + CLIENT_ID));
        assertFalse("Request body must omit client secret when null/empty",
                requestBody.contains("&client_secret="));
    }

    @Test
    public void test_createRequestBody_WithClientSecret() {
        String secret = "E1FD9FE9AB38CD8D3E01FE370C82";
        when(mockConfig.getClientSecret()).thenReturn(secret);

        String requestBody = flow.createRequestBody(mockConfig);

        assertTrue("Request body should contain client secret when present.",
                requestBody.contains("&client_secret=" + secret));
    }

    @Test
    public void test_createHeaders_ContainsCorrectContentTypeAndAccept() {
        Map<String, String> headers = flow.createHeaders(mockConfig);

        assertEquals("Unexpected value for Content-Type header",
                "application/x-www-form-urlencoded", headers.get("Content-Type"));
        assertEquals("Unexpected value for accept header",
                "application/json", headers.get("Accept"));
        assertNull("Request Authorization header must be null/omitted when credentials are in the body",
                headers.get(AbstractOAuthFlow.AUTHORIZATION_HEADER));
    }

    @Test
    public void test_getToken_SuccessfulExecution_VerifiesParameters_WithoutSecret() throws Exception {

        flowSpy.getToken(mockConfig);

        verify(flowSpy, times(1)).executeTokenRequest(
                eq(mockConfig), any(String.class), any(Map.class), any(String.class));

        Map<String, Object> params = captureExecutionParameters(flowSpy);
        String capturedBody = (String) params.get("BODY");
        Map<String, String> capturedHeaders = (Map<String, String>) params.get("HEADERS");

        assertTrue("Request body must contain grant_type",
                capturedBody.contains("grant_type=refresh_token"));
        assertTrue("Request body must contain refresh_token",
                capturedBody.contains("&refresh_token=" + REFRESH_TOKEN));
        assertTrue("Request body must contain client_id",
                capturedBody.contains("&client_id=" + CLIENT_ID));
        assertFalse("Request body should omit client_secret when null or empty",
                capturedBody.contains("&client_secret="));

        assertNull("Request should not have Authorization header as credentials are passed in the request body",
                capturedHeaders.get(AbstractOAuthFlow.AUTHORIZATION_HEADER));
    }

    @Test
    public void test_getToken_SuccessfulExecution_VerifiesParameters_WithSecret() throws Exception {
        when(mockConfig.getClientSecret()).thenReturn(CLIENT_SECRET);

        flowSpy.getToken(mockConfig);

        Map<String, Object> params = captureExecutionParameters(flowSpy);
        String capturedBody = (String) params.get("BODY");

        assertTrue("Request body must contain client_secret",
                capturedBody.contains("&client_secret=" + CLIENT_SECRET));
    }

    @Test
    public void test_GetToken_ThrowsConnectionException_WhenHttpEError() throws Exception {
        when(mockTransport.connect(eq(TOKEN_ENDPOINT), any(HashMap.class), eq(false)))
                .thenThrow(new IOException("Test message for IO exception"));
        ConnectionException thrownException = assertThrows(ConnectionException.class, () -> {
            flow.getToken(mockConfig);
        });
        assertTrue("Invalid error message returned in the exception",
                thrownException.getMessage().contains("Error establishing token request connection with error"));
    }
}
