package com.bing.lan.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.DaoUrlAuthorizationConfigurer;

/**
 * Created by lb on 2020/5/4.
 */
@Configuration
@Order(200)
public class ManagerWebSecurityConfigurer extends BaseWebSecurityConfigurer {

    private static final String MANAGER_LOGIN_URL = "/manager/login";

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/manager/**");
        super.configure(http);
    }

    @Override
    protected String loginProcessingUrl() {
        return MANAGER_LOGIN_URL;
    }

    @Override
    protected JwtSecurityContextRepository jwtSecurityContextRepository() {
        return new JwtSecurityContextRepository(MANAGER_LOGIN_URL);
    }

    @Override
    protected DaoUrlAuthorizationConfigurer daoUrlAuthorizationConfigurer() {
        return new DaoUrlAuthorizationConfigurer(true);
    }
}
