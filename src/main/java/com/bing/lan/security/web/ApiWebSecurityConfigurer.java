package com.bing.lan.security.web;

import com.bing.lan.security.JwtSecurityContextRepository;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configurers.DaoUrlAuthorizationConfigurer;

/**
 * Created by lb on 2020/4/25.
 */
@Configuration
@Order(100)
public class ApiWebSecurityConfigurer extends BaseWebSecurityConfigurer {

    private static final String API_LOGIN_URL = "/api/login";

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
        // 需要忽略的资源
        web.ignoring().antMatchers(/*"/js/**", "/css/**", "/images/**",*/
                "/favicon.ico", "/error");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/api/**");
        super.configure(http);
    }

    @Override
    protected String loginProcessingUrl() {
        return API_LOGIN_URL;
    }

    @Override
    protected JwtSecurityContextRepository jwtSecurityContextRepository() {
        return new JwtSecurityContextRepository(API_LOGIN_URL);
    }

    @Override
    protected DaoUrlAuthorizationConfigurer daoUrlAuthorizationConfigurer() {
        return new DaoUrlAuthorizationConfigurer(false);
    }
}
