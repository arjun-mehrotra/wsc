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
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public abstract class AbstractOAuthFlowTestBase {

    protected static final String CLIENT_ID = "testClientId";
    protected static final String CLIENT_SECRET = "testClientSecret";
    protected static final String TOKEN_ENDPOINT = "https://test-org.my.salesforce.com/services/oauth2/token";
    protected static final String SUCCESS_RESPONSE_JSON = "{\"access_token\": \"test_access_token\", \"token_type\": \"bearer\"}";
    protected static final String ERROR_RESPONSE_JSON = "{\"error\": \"test_error\", \"error_description\": \"Test error description\"}";

    protected AbstractOAuthFlow flow;
    protected ConnectorConfig mockConfig;
    protected Transport mockTransport;
    protected ByteArrayOutputStream mockTransportOutStream;

    @Before
    public void setUpBase() throws ConnectionException, IOException, OAuthException {
        mockConfig = mock(ConnectorConfig.class);
        mockTransport = mock(Transport.class);
        mockTransportOutStream = new ByteArrayOutputStream();

        when(mockConfig.getClientId()).thenReturn(CLIENT_ID);
        when(mockConfig.getClientSecret()).thenReturn(CLIENT_SECRET);
        when(mockConfig.getTokenEndpoint()).thenReturn(TOKEN_ENDPOINT);
        when(mockConfig.createTransport()).thenReturn(mockTransport);

        when(mockTransport.connect(eq(TOKEN_ENDPOINT), any(HashMap.class), eq(false)))
                .thenReturn(mockTransportOutStream);

        setUpFlows();
    }

    protected abstract void setUpFlows() throws OAuthException, IOException, ConnectionException;

    protected Map<String, Object> captureExecutionParameters(AbstractOAuthFlow spyFlow) throws Exception {
        ArgumentCaptor<String> endpointCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Map> headersCaptor = ArgumentCaptor.forClass(Map.class);
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);

        verify(spyFlow, times(1)).executeTokenRequest(
                eq(mockConfig), endpointCaptor.capture(), headersCaptor.capture(), bodyCaptor.capture());

        Map<String, Object> results = new HashMap<>();
        results.put("ENDPOINT", endpointCaptor.getValue());
        results.put("HEADERS", headersCaptor.getValue());
        results.put("BODY", bodyCaptor.getValue());
        return results;
    }

    @Test
    public void test_GetToken_ThrowsOAuthException_WhenInvalidConfig() throws Exception {
        OAuthException thrownException = assertThrows(OAuthException.class, () -> {
            flow.getToken(null);
        });
        assertTrue("Exception message should indicate missing config",
                thrownException.getMessage().contains("Invalid OAuth configuration"));
    }

    @Test
    public void test_ExecuteTokenRequest_SuccessfulServerResponse() throws Exception {
        InputStream mockInStream = new ByteArrayInputStream(SUCCESS_RESPONSE_JSON.getBytes(StandardCharsets.UTF_8));
        when(mockTransport.isSuccessful()).thenReturn(true);
        when(mockTransport.getContent()).thenReturn(mockInStream);

        OAuthTokenResponse response = flow.executeTokenRequest(mockConfig, TOKEN_ENDPOINT, new HashMap<>(), "");
        assertNotNull(response);
    }

    @Test
    public void test_ExecuteTokenRequest_ErrorServerResponse() throws Exception {
        InputStream mockInStream = new ByteArrayInputStream(ERROR_RESPONSE_JSON.getBytes(StandardCharsets.UTF_8));
        when(mockTransport.isSuccessful()).thenReturn(false);
        when(mockTransport.getContent()).thenReturn(mockInStream);

        OAuthException thrownException = assertThrows(OAuthException.class, () -> {
            flow.executeTokenRequest(mockConfig, TOKEN_ENDPOINT, new HashMap<>(), "");
        });
        assertEquals("Invalid error code returned in the exception",
                "test_error", thrownException.getErrorCode());
        assertEquals("Invalid error description returned in the exception",
                "Test error description", thrownException.getErrorDescription());
    }
}
