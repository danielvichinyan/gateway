package com.knowit.gateway.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    private final Algorithm algorithm;

    public JwtService(@Value("${gateway.app.jwtSecret}") String jwtSecret)
            throws IllegalArgumentException {
        this.algorithm = Algorithm.HMAC512(jwtSecret);
    }

    public DecodedJWT verifyToken(String token) {
        final JWTVerifier jwtVerifier = JWT.require(this.algorithm).build();
        try {
            return jwtVerifier.verify(token);
        } catch (JWTVerificationException exception) {
            exception.printStackTrace();
        }
        return null;
    }
}
