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

package com.sforce.oauth.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class OAuthTokenResponseTest {

    private ObjectMapper mapper;

    private static final String FULL_RESPONSE_JSON =
            "{" +
                    "\"access_token\":\"sample_token_12345\"," +
                    "\"refresh_token\":\"sample_refresh_token_7890\"," +
                    "\"token_type\":\"Bearer\"," +
                    "\"scope\":\"id profile api\"," +
                    "\"instance_url\":\"https://na1.salesforce.com\"," +
                    "\"id\":\"https://na1.salesforce.com/id/00Dxx/005xx\"," +
                    "\"issued_at\":\"1678886400000\"," +
                    "\"signature\":\"signature_hash_xyz\"" +
                    "}";

    private static final String MINIMAL_RESPONSE_JSON =
            "{" +
                    "\"access_token\":\"minimal_token\"," +
                    "\"token_type\":\"Bearer\"," +
                    "\"extra_field\":\"should_be_ignored\"" +
                    "}";

    @Before
    public void setup() {
        mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    @Test
    public void testJsonDeserialization() throws IOException {
        OAuthTokenResponse response = mapper.readValue(FULL_RESPONSE_JSON, OAuthTokenResponse.class);

        assertNotNull(response);
        assertEquals("sample_token_12345", response.getAccessToken());
        assertEquals("sample_refresh_token_7890", response.getRefreshToken());
        assertEquals("Bearer", response.getTokenType());
        assertEquals("id profile api", response.getScope());
        assertEquals("https://na1.salesforce.com", response.getInstanceUrl());
        assertEquals("https://na1.salesforce.com/id/00Dxx/005xx", response.getId());
        assertEquals("1678886400000", response.getIssuedAt());
        assertEquals("signature_hash_xyz", response.getSignature());
    }

    @Test
    public void testJsonDeserialization_WithPartialJSON() throws IOException {
        OAuthTokenResponse response = mapper.readValue(MINIMAL_RESPONSE_JSON, OAuthTokenResponse.class);

        assertNotNull(response);
        assertEquals("minimal_token", response.getAccessToken());
        assertEquals("Bearer", response.getTokenType());

        assertNull(response.getScope());
        assertNull(response.getInstanceUrl());
        assertNull(response.getId());
        assertNull(response.getIssuedAt());
        assertNull(response.getSignature());
    }

    @Test
    public void test_toString_masks_sensitive_fields() throws JsonProcessingException {
        OAuthTokenResponse response = mapper.readValue(FULL_RESPONSE_JSON, OAuthTokenResponse.class);
        String result = response.toString();

        assertTrue("Access token should be masked", result.contains("accessToken='*******************'"));
        assertFalse("Access token should not be written out", result.contains("sample_token_12345"));
        assertTrue("Refresh token should be masked", result.contains("refreshToken='*******************'"));
        assertFalse("Refresh token should not be written out", result.contains("sample_refresh_token_7890"));
        assertTrue("Signature should be masked", result.contains("signature='*******************'"));
        assertFalse("Signature token should not be written out", result.contains("signature_hash_xyz"));
    }
}
