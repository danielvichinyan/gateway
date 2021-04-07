package com.knowit.gateway.security.filters;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.knowit.gateway.services.JwtService;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

@Component
public class AuthenticationZuulFilter extends ZuulFilter {

    private static final String X_USER_ID = "X-User-Id";

    private static final String X_USER_SCOPES = "X-User-Scopes";

    private String[] userRoles;

    private JwtService jwtService;

    public AuthenticationZuulFilter(JwtService jwtService) {
        this.jwtService = jwtService;
        this.userRoles = new String[]{};
    }

    @Override
    public String filterType() {
        return FilterConstants.PRE_TYPE;
    }

    @Override
    public int filterOrder() {
        return FilterConstants.PRE_DECORATION_FILTER_ORDER;
    }

    @Override
    public boolean shouldFilter() {
        RequestContext requestContext = RequestContext.getCurrentContext();
        HttpServletRequest request = requestContext.getRequest();

        return !(request.getRequestURI().startsWith("/api/auth"));
    }

    @Override
    public Object run() throws ZuulException {
        RequestContext requestContext = RequestContext.getCurrentContext();
        HttpServletRequest request = requestContext.getRequest();
        String authHeader =  request.getHeader("Authorization");
        String tokenFromHeader = this.extractTokenFromAuthorizationHeader(authHeader);
        DecodedJWT decodedJWT = this.jwtService.validateToken(tokenFromHeader);
        String userId = decodedJWT.getKeyId();

        if (decodedJWT.equals(null)) {
            throw new ZuulException("Invalid token!", HttpStatus.UNAUTHORIZED.value(), "Invalid token signature!");
        }
        this.addHeaders(requestContext, userId);

        return null;
    }

    public static String extractTokenFromAuthorizationHeader(String header) {
        String token = header.replace("Bearer ", "");

        return token.trim();
    }

    private void addHeaders(RequestContext requestContext, String id) {
        requestContext.addZuulRequestHeader(X_USER_ID, id);
        requestContext.addZuulRequestHeader(X_USER_SCOPES, String.valueOf(this.userRoles));
    }
}
