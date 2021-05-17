package com.knowit.gateway.services.jwt;

import com.auth0.jwt.interfaces.DecodedJWT;

public interface JwtService {

    DecodedJWT getVerifiedToken(String token);
}
