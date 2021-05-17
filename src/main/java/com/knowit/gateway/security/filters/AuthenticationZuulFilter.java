package com.knowit.gateway.security.filters;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.knowit.gateway.services.jwt.JwtService;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;


@Component
public class AuthenticationZuulFilter extends ZuulFilter {

    private static final String X_USER_ID = "X-User-Id";
    private static final String X_USER_SCOPES = "X-User-Scopes";

    private final JwtService jwtService;

    public AuthenticationZuulFilter(JwtService jwtService) {
        this.jwtService = jwtService;
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

        String authorizationHeader = request.getHeader("Authorization");
        String tokenFromHeader = this.getTokenFromAuthorizationHeader(authorizationHeader);
        DecodedJWT decodedToken = this.jwtService.getVerifiedToken(tokenFromHeader);
        String userId = decodedToken.getKeyId();
        Claim userRole = decodedToken.getClaim("roles");
        String [] roles = userRole.asString().split(",");

        if (decodedToken.equals(null)) {
            throw new ZuulException("Invalid token.", HttpStatus.UNAUTHORIZED.value(), "Token signature is invalid.");
        }

        this.addClaimsToRequestAsHeaders(requestContext, userId, roles);

        return null;
    }

    public static String getTokenFromAuthorizationHeader(String header) {
        String token = header.replace("Bearer ", "");

        return token.trim();
    }

    private void addClaimsToRequestAsHeaders(RequestContext requestContext, String id, String [] roles) {
        requestContext.addZuulRequestHeader(X_USER_ID, id);
        requestContext.addZuulRequestHeader(X_USER_SCOPES, Arrays.toString(roles));
    }
}
