package com.bing.lan.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 * Created by lb on 2020/4/25.
 */
@Configuration
public class WebSecurityConfigurerInfo extends WebSecurityConfigurerAdapter {

    public WebSecurityConfigurerInfo() {
        // 取消默认配置
        super(true);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    public void init(WebSecurity web) throws Exception {
        super.init(web);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
        // 需要忽略的资源
        web.ignoring().antMatchers(/*"/js/**", "/css/**", "/images/**",*/
                "/favicon.ico", "/error");
    }

    @Bean
    JwtSecurityContextRepository jwtSecurityContextRepository() {
        return new JwtSecurityContextRepository();
    }

    /**
     * 配置角色继承
     */
    @Bean
    RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
        return hierarchy;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 配置用户
        auth.inMemoryAuthentication().withUser("coco").password("123").roles("USER");
        auth.inMemoryAuthentication().withUser("lili").password("123").roles("ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //super.configure(http);

        // 配置日志拦截器
        http.addFilterBefore(new LogFilter(), WebAsyncManagerIntegrationFilter.class);

        // 配置SecurityContext的默认持久化方式，即存在HttpSession中
        http.securityContext(securityContextConfigurer -> {
            // 将持久化方式改为 jwt token 方式
            securityContextConfigurer.securityContextRepository(jwtSecurityContextRepository());
        });

        // 配置认证拦截器，做登录操作
        http.formLogin(formLoginConfigurer -> {
            // 配置登录后跳转地址
            //formLoginConfigurer.defaultSuccessUrl("/hello");
            // 登录成功后不做操作，留给 JwtSecurityContextRepository.saveContext()操作
            formLoginConfigurer.successHandler((req, resp, authentication) -> {
            });
        });

        // 配置匿名拦截器，如果未认证，则自动添加匿名认证
        http.anonymous(httpSecurityAnonymousConfigurer -> {

        });

        // 配置授权拦截器
        http.authorizeRequests(expressionInterceptUrlRegistry -> {
            expressionInterceptUrlRegistry.antMatchers("/user/**").hasRole("USER");
            expressionInterceptUrlRegistry.antMatchers("/admin/**").hasRole("ADMIN");
            expressionInterceptUrlRegistry.antMatchers("/denyAll").denyAll();
            expressionInterceptUrlRegistry.antMatchers("/anonymous").anonymous();
            expressionInterceptUrlRegistry.anyRequest().authenticated();
        });
    }

    /**
     * 日志拦截器
     */
    static class LogFilter implements Filter {

        @Override
        public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
            String servletPath = ((HttpServletRequest) servletRequest).getServletPath();
            System.out.println(">>>>>>>>>>>>> doFilter() servletPath: " + servletPath);
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }
}
