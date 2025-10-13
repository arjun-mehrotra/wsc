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

package com.sforce.oauth.util;

import org.junit.Test;

import static org.junit.Assert.*;

public class OAuthUtilTest {

    @Test(expected = IllegalArgumentException.class)
    public void test_buildBasicAuthHeader_NullClientIdThrowsException() {
        String clientId = null;
        String clientSecret = "clientSecret";
        OAuthUtil.buildBasicAuthHeader(clientId, clientSecret);
    }

    @Test(expected = IllegalArgumentException.class)
    public void test_buildBasicAuthHeader_EmptyClientIdThrowsException() {
        String clientId = "";
        String clientSecret = "clientSecret";
        OAuthUtil.buildBasicAuthHeader(clientId, clientSecret);
    }

    @Test(expected = IllegalArgumentException.class)
    public void test_buildBasicAuthHeader_WhitespaceClientIdThrowsException() {
        String clientId = "   ";
        String clientSecret = "clientSecret";
        OAuthUtil.buildBasicAuthHeader(clientId, clientSecret);
    }

    @Test(expected = IllegalArgumentException.class)
    public void test_buildBasicAuthHeader_NullClientSecretThrowsException() {
        String clientId = "clientId";
        String clientSecret = null;
        OAuthUtil.buildBasicAuthHeader(clientId, clientSecret);
    }

    @Test(expected = IllegalArgumentException.class)
    public void test_buildBasicAuthHeader_EmptyClientSecretThrowsException() {
        String clientId = "clientId";
        String clientSecret = "";
        OAuthUtil.buildBasicAuthHeader(clientId, clientSecret);
    }

    @Test(expected = IllegalArgumentException.class)
    public void test_buildBasicAuthHeader_WhitespaceClientSecretThrowsException() {
        String clientId = "clientId";
        String clientSecret = "   ";
        OAuthUtil.buildBasicAuthHeader(clientId, clientSecret);
    }

    @Test
    public void test_buildBasicAuthHeader_ValidCredentials() {
        String clientId = "test_client_id";
        String clientSecret = "test_client_secret";

        String authHeader = OAuthUtil.buildBasicAuthHeader(clientId, clientSecret);

        assertNotNull("Authorization header should not be null", authHeader);
        assertTrue("Authorization header should start with 'Basic '", authHeader.startsWith("Basic "));

        String encodedPart = authHeader.substring(6);
        assertFalse("Encoded part should not be empty", encodedPart.isEmpty());
        
        String decoded = new String(java.util.Base64.getDecoder().decode(encodedPart));
        assertEquals("Decoded credentials should match the original input",
                clientId + ":" + clientSecret, decoded);
    }

    @Test
    public void testBuildBasicAuthHeader_WithSpecialCharacters() {
        String clientId = "client@domain.com";
        String clientSecret = "secret!@#$%^&*()==";

        String authHeader = OAuthUtil.buildBasicAuthHeader(clientId, clientSecret);

        assertNotNull("Authorization header should not be null", authHeader);
        assertTrue("Authorization header should start with 'Basic '", authHeader.startsWith("Basic "));

        String encodedPart = authHeader.substring(6);
        assertFalse("Encoded part should not be empty", encodedPart.isEmpty());

        String decoded = new String(java.util.Base64.getDecoder().decode(encodedPart));
        assertEquals("Decoded credentials should match the original input",
                clientId + ":" + clientSecret, decoded);
    }
}
