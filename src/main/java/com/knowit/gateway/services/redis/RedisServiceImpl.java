package com.knowit.gateway.services.redis;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class RedisServiceImpl implements RedisService {

    private final RedisTemplate<String, String> redisTemplate;

    @Autowired
    public RedisServiceImpl(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void setToken(String tokenKey, String tokenValue, long expire) {
        this.redisTemplate.opsForValue().set(tokenKey, tokenValue, expire / 1000, TimeUnit.SECONDS);
    }

    @Override
    public String getToken(String tokenKey) {

        return this.redisTemplate.opsForValue().get(tokenKey);
    }
}

