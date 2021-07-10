package com.knowit.gateway.services.jwt;

import com.knowit.gateway.services.redis.RedisService;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtServiceImpl implements JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtServiceImpl.class);

    private final Algorithm algorithm;
    private final RedisService redisService;

    public JwtServiceImpl(
            @Value("${gateway.app.jwtSecret}") String jwtSecret,
            RedisService redisService
    ) {
        this.algorithm = Algorithm.HMAC512(jwtSecret);
        this.redisService = redisService;
    }

    @Override
    public DecodedJWT getVerifiedToken(String token) {
        if (this.redisService.getToken(token) == null) {
            return this.verifyToken(token);
        }

        return this.getDecodedToken(token);
    }

    private DecodedJWT getDecodedToken(String token) {

        return JWT.decode(token);
    }

    private DecodedJWT verifyToken(String token) {
        JWTVerifier verifier = JWT.require(this.algorithm).build();
        this.redisService.setToken(
                verifier.verify(token).getToken(),
                verifier.verify(token).getKeyId(),
                verifier.verify(token).getExpiresAt().getTime()
        );
        logger.info("Successful save JWT in database");

        return verifier.verify(token);
    }
}