package com.bing.lan.security.webflux;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Created by lb on 2020/4/29.
 */
@Configuration
public class HelloWebfluxSecurityConfigurer {

    @Bean
    public MapReactiveUserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("user")
                .roles("USER")
                .build();
        return new MapReactiveUserDetailsService(user);
    }

    @Bean
    public SecurityWebFilterChain ignoreSpringSecurityFilterChain(ServerHttpSecurity http) {
        http.securityMatcher(ServerWebExchangeMatchers.pathMatchers("/api/favicon.ico", "/api/error"));

        http.authenticationManager(null);
        http.logout().disable();
        http.csrf().disable();
        //http.cors().disable();
        http.headers().disable();
        http.requestCache().disable();
        http.authorizeExchange(authorizeExchangeSpec -> {
            authorizeExchangeSpec.anyExchange().permitAll();
        });
        return http.build();
        // todo 直接放行
        //ServerWebExchangeMatcher matcher = ServerWebExchangeMatchers.pathMatchers("/api/favicon.ico", "/api/error", "/api/hello");
        //List<WebFilter> filters = new ArrayList<>();
        //filters.add(new WebFilter() {
        //
        //    @Override
        //    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        //        return Mono.justOrEmpty(null);
        //    }
        //});
        //
        //return new MatcherSecurityWebFilterChain(matcher, filters);
    }

    @Bean
    public SecurityWebFilterChain apiSpringSecurityFilterChain(ServerHttpSecurity http) {
        http.securityMatcher(ServerWebExchangeMatchers.pathMatchers("/api/**"));

        http.authorizeExchange(authorizeExchangeSpec -> {
            authorizeExchangeSpec.anyExchange().authenticated();
        });

        http.httpBasic(withDefaults());
        http.formLogin(withDefaults());
        http.csrf().disable();
        return http.build();
    }

    @Bean
    public SecurityWebFilterChain managerSpringSecurityFilterChain(ServerHttpSecurity http) {
        http.securityMatcher(ServerWebExchangeMatchers.pathMatchers("/manager/**"));

        http.headers().disable();
        http.logout().disable();
        return http.build();
    }
}
