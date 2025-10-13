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
import com.sforce.ws.transport.Transport;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ClientCredentialsFlowTest {

    private ClientCredentialsFlow flow;
    private ConnectorConfig mockConfig;
    private Transport mockTransport;
    private ByteArrayOutputStream mockTransportOutStream;

    private static final String CLIENT_ID = "testClientId";
    private static final String CLIENT_SECRET = "testClientSecret";
    private static final String TOKEN_ENDPOINT = "https://login.salesforce.com/oauth/token";
    private static final String SUCCESS_RESPONSE_JSON = "{\"access_token\": \"test_access_token\", \"token_type\": \"bearer\", \"expires_in\": 3600}";
    private static final String ERROR_RESPONSE_JSON = "{\"error\": \"invalid_client\", \"error_description\": \"Invalid client credentials\"}";

    @Before
    public void setUp() throws IOException, ConnectionException {
        flow = new ClientCredentialsFlow();
        mockConfig = mock(ConnectorConfig.class);
        mockTransport = mock(Transport.class);
        mockTransportOutStream = new ByteArrayOutputStream();

        when(mockConfig.getClientId()).thenReturn(CLIENT_ID);
        when(mockConfig.getClientSecret()).thenReturn(CLIENT_SECRET);
        when(mockConfig.getTokenEndpoint()).thenReturn(TOKEN_ENDPOINT);
        when(mockConfig.createTransport()).thenReturn(mockTransport);

        when(mockTransport
                .connect(eq(TOKEN_ENDPOINT), any(HashMap.class), eq(false)))
                .thenReturn(mockTransportOutStream);
    }

    @Test
    public void test_GetToken_WithSuccessfulTokenRetrieval() throws Exception {
        InputStream mockInStream = new ByteArrayInputStream(SUCCESS_RESPONSE_JSON.getBytes(StandardCharsets.UTF_8));
        when(mockTransport.isSuccessful()).thenReturn(true);
        when(mockTransport.getContent()).thenReturn(mockInStream);

        OAuthTokenResponse response = flow.getToken(mockConfig);

        assertNotNull(response);
        assertEquals("Token response should return an access token",
                "test_access_token", response.getAccessToken());

        String requestBody = mockTransportOutStream.toString();
        assertTrue("Request body should contain client_credentials grant type",
                requestBody.contains("grant_type=client_credentials"));

        ArgumentCaptor<HashMap<String, String>> headersCaptor = ArgumentCaptor.forClass(HashMap.class);
        verify(mockTransport).connect(eq(TOKEN_ENDPOINT), headersCaptor.capture(), eq(false));

        HashMap<String, String> capturedHeaders = headersCaptor.getValue();
        assertNotNull("Authorization header should be present in the request",
                capturedHeaders.get("Authorization"));
        assertEquals("Content-Type header should be set to application/x-www-form-urlencoded",
                "application/x-www-form-urlencoded", capturedHeaders.get("Content-Type"));
    }

    @Test
    public void test_GetToken_ThrowsOAuthException_WhenServerReturnsAnError() throws Exception {

        InputStream mockErrorStream = new ByteArrayInputStream(ERROR_RESPONSE_JSON.getBytes(StandardCharsets.UTF_8));
        when(mockTransport.isSuccessful()).thenReturn(false);
        when(mockTransport.getContent()).thenReturn(mockErrorStream);

        OAuthException thrownException = assertThrows(OAuthException.class, () -> {
            flow.getToken(mockConfig);
        });
        assertEquals("Invalid error code returned in the exception",
                "invalid_client", thrownException.getErrorCode());
        assertEquals("Invalid error description returned in the exception",
                "Invalid client credentials", thrownException.getErrorDescription());
    }

    @Test
    public void test_GetToken_ThrowsOAuthException_WhenInvalidConfig() throws Exception {
        when(mockConfig.getClientSecret()).thenReturn(null);
        OAuthException thrownException = assertThrows(OAuthException.class, () -> {
            flow.getToken(mockConfig);
        });
        assertTrue("Invalid error message returned in the exception",
                thrownException.getMessage().contains("Invalid OAuth configuration"));
        assertNull("Invalid error code returned in the exception", thrownException.getErrorCode());
        assertNull("Invalid error description returned in the exception", thrownException.getErrorDescription());
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

    @Test
    public void test_GetToken_ThrowsRuntimeException_WhenUnknownError() throws Exception {
        when(mockTransport.connect(eq(TOKEN_ENDPOINT), any(HashMap.class), eq(false)))
                .thenThrow(new RuntimeException("Test message for runtime exception"));
        ConnectionException thrownException = assertThrows(ConnectionException.class, () -> {
            flow.getToken(mockConfig);
        });
        assertTrue("Invalid error message returned in the exception",
                thrownException.getMessage().contains("An unexpected error occurred during the OAuth flow"));
    }

    @Test
    public void test_GetToken_ThrowsConnectionException_WhenReadingResponse() throws Exception {
        when(mockTransport.isSuccessful()).thenReturn(true);
        when(mockTransport.getContent()).thenThrow(new IOException("Test message for IO exception"));

        ConnectionException thrownException = assertThrows(ConnectionException.class, () -> {
            flow.getToken(mockConfig);
        });
        assertTrue(thrownException.getMessage().contains("Error establishing token request connection"));
        assertTrue(thrownException.getCause() instanceof IOException);
    }
}