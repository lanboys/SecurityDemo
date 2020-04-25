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
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Created by lb on 2020/4/26.
 */
public class JwtSecurityContextRepository implements SecurityContextRepository {

    private static final String AUTHORIZATION = "authorization";
    private static final String AUTHORITIES = "authorities";
    private static final String SIGNING_KEY = "sign123";

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        HttpServletRequest servletRequest = requestResponseHolder.getRequest();

        String servletPath = servletRequest.getServletPath();
        String jwtToken = getAuthentication(servletRequest);
        System.out.println("loadContext servletPath: " + servletPath);
        System.out.println("loadContext jwtToken: " + jwtToken);
        // todo 校验有效期
        if (StringUtils.isEmpty(jwtToken) || "/login".equals(servletPath)) {
            return SecurityContextHolder.createEmptyContext();
        }

        Claims claims = Jwts.parser().setSigningKey(SIGNING_KEY)
                .parseClaimsJws(jwtToken.replace("Bearer", "")).getBody();
        String username = claims.getSubject();//获取当前登录用户名
        List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList((String) claims.get(AUTHORITIES));

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, null, authorities);
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(token);
        return context;
    }

    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        final Authentication authentication = context.getAuthentication();
        if (authentication == null || trustResolver.isAnonymous(authentication)) {
            return;
        }

        String servletPath = request.getServletPath();
        System.out.println("saveContext servletPath: " + servletPath);
        if (!"/login".equals(servletPath)) {
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
        try {
            response.setContentType("application/json;charset=utf-8");
            response.addCookie(new Cookie(AUTHORIZATION, jwtToken));
            response.getWriter().write(new ObjectMapper().writeValueAsString("login success"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return false;
    }

    public String getAuthentication(HttpServletRequest request) {
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
