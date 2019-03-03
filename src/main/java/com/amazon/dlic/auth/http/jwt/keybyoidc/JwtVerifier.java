/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.dlic.auth.http.jwt.keybyoidc;

import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactConsumer;
import org.apache.cxf.rs.security.jose.jws.JwsSignatureVerifier;
import org.apache.cxf.rs.security.jose.jws.JwsUtils;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.apache.cxf.rs.security.jose.jwt.JwtException;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.cxf.rs.security.jose.jwt.JwtUtils;

import com.google.common.base.Strings;

public class JwtVerifier {

	private final KeyProvider keyProvider;

	public JwtVerifier(KeyProvider keyProvider) {
		this.keyProvider = keyProvider;
	}

	public JwtToken getVerifiedJwtToken(String encodedJwt) throws BadCredentialsException {
		try {
			JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(encodedJwt);
			JwtToken jwt = jwtConsumer.getJwtToken();
			JsonWebKey key = keyProvider.getKey(jwt.getJwsHeaders().getKeyId());
			JwsSignatureVerifier signatureVerifier = getInitializedSignatureVerifier(key);

			boolean signatureValid = jwtConsumer.verifySignatureWith(signatureVerifier);

			if (!signatureValid && Strings.isNullOrEmpty(jwt.getJwsHeaders().getKeyId())) {
				key = keyProvider.getKeyAfterRefresh(null);
				signatureVerifier = getInitializedSignatureVerifier(key);
				signatureValid = jwtConsumer.verifySignatureWith(signatureVerifier);
			}

			if (!signatureValid) {
				throw new BadCredentialsException("Invalid JWT signature");
			}

			validateClaims(jwt);

			return jwt;
		} catch (JwtException e) {
			throw new BadCredentialsException(e.getMessage(), e);
		}
	}

	private JwsSignatureVerifier getInitializedSignatureVerifier(JsonWebKey key)
			throws BadCredentialsException, JwtException {
		JwsSignatureVerifier result = JwsUtils.getSignatureVerifier(key);

		if (result == null) {
			throw new BadCredentialsException("Cannot verify JWT");
		} else {
			return result;
		}
	}

	private void validateClaims(JwtToken jwt) throws BadCredentialsException, JwtException {
		JwtClaims claims = jwt.getClaims();

		if (claims != null) {
			JwtUtils.validateJwtExpiry(claims, 0, false);
			JwtUtils.validateJwtNotBefore(claims, 0, false);
		}
	}
}
