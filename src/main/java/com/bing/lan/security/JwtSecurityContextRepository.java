package com.bing.lan.security;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Created by lb on 2020/4/26.
 */
public class JwtSecurityContextRepository implements SecurityContextRepository {

    private static final String AUTHORIZATION = "authorization";
    private static final String AUTHORITIES = "authorities";
    private static final String SIGNING_KEY = "sign123";
    private String LOGIN_URL = "/login";

    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    public JwtSecurityContextRepository() {
    }

    public JwtSecurityContextRepository(String loginUrl) {
        this.LOGIN_URL = loginUrl;
    }

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        HttpServletRequest servletRequest = requestResponseHolder.getRequest();

        String jwtToken = getAuthentication(servletRequest);
        //System.out.println("loadContext jwtToken: " + jwtToken);

        if (StringUtils.isEmpty(jwtToken) || LOGIN_URL.equals(servletRequest.getServletPath())) {
            return SecurityContextHolder.createEmptyContext();
        }

        // redis 单点登录
        Claims claims;
        try {
            claims = Jwts.parser().setSigningKey(SIGNING_KEY)
                    .parseClaimsJws(jwtToken.replace("Bearer", "")).getBody();
        } catch (ExpiredJwtException throwable) {
            throw new SecurityException("token 过期");
        }

        String username = claims.getSubject();//获取当前登录用户名
        List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList((String) claims.get(AUTHORITIES));

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, null, authorities);
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(token);
        return context;
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        final Authentication authentication = context.getAuthentication();

        if (authentication == null || trustResolver.isAnonymous(authentication)) {
            return;
        }

        if (!LOGIN_URL.equals(request.getServletPath())) {
            return;
        }

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        StringBuffer as = new StringBuffer();
        for (GrantedAuthority authority : authorities) {
            as.append(authority.getAuthority()).append(",");
        }

        String jwtToken = Jwts.builder()
                .claim(AUTHORITIES, as)//配置用户角色
                .setSubject(authentication.getName())
                .setExpiration(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                .signWith(SignatureAlgorithm.HS512, SIGNING_KEY)
                .compact();

        System.out.println("saveContext jwtToken: " + jwtToken);
        response.addCookie(new Cookie(AUTHORIZATION, jwtToken));
        returnResult(response, "登录成功");
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return false;
    }

    private void returnResult(HttpServletResponse response, String result) {
        try {
            response.setContentType("application/json;charset=utf-8");
            PrintWriter writer = response.getWriter();
            writer.write(new ObjectMapper().writeValueAsString(result));
            writer.flush();
            writer.close();
        } catch (IOException e) {
            throw new SecurityException(e);
        }
    }

    private String getAuthentication(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (null == cookies) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (AUTHORIZATION.equals(cookie.getName())) {
                return StringUtils.isEmpty(cookie.getValue()) ? null : cookie.getValue();
            }
        }
        return null;
    }
}
