package com.knowit.gateway.services.redis;

public interface RedisService {

    void setToken(String tokenKey, String tokenValue, long expire);

    String getToken(String tokenKey);
}
