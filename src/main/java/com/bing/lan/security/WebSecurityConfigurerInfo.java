package com.bing.lan.security;

import com.fasterxml.jackson.databind.ObjectMapper;

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
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

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

        // 配置异常拦截器
        http.addFilterBefore(new ExceptionFilter(), WebAsyncManagerIntegrationFilter.class);
        // 配置日志拦截器
        http.addFilterBefore(new LogFilter(), ExceptionFilter.class);

        // 配置SecurityContext的默认持久化方式，即存在HttpSession中
        http.securityContext(securityContextConfigurer -> {
            // 将持久化方式改为 jwt 方式
            securityContextConfigurer.securityContextRepository(jwtSecurityContextRepository());
        });

        // 配置认证拦截器，做登录操作
        http.formLogin(formLoginConfigurer -> {
            // 配置登录后跳转地址
            //formLoginConfigurer.defaultSuccessUrl("/hello");

            // 登录成功后不做操作，留给 JwtSecurityContextRepository.saveContext()操作
            formLoginConfigurer.successHandler((req, resp, authentication) -> {
                System.out.println("configure() 登录成功");
            });
            formLoginConfigurer.failureHandler((request, response, exception) -> {
                System.out.println("configure() 登录失败: " + exception.getLocalizedMessage());
                throw new SecurityException("登录失败");
            });
        });

        // 配置匿名拦截器，如果未认证，则自动添加匿名认证
        http.anonymous(anonymousConfigurer -> {

        });

        // 配置授权拦截器
        http.authorizeRequests(expressionInterceptUrlRegistry -> {
            expressionInterceptUrlRegistry.antMatchers("/user/**").hasRole("USER");
            expressionInterceptUrlRegistry.antMatchers("/admin/**").hasRole("ADMIN");
            expressionInterceptUrlRegistry.antMatchers("/denyAll").denyAll();
            expressionInterceptUrlRegistry.antMatchers("/anonymous").anonymous();
            expressionInterceptUrlRegistry.anyRequest().authenticated();
        });

        http.requestCache(requestCacheConfigurer -> {
            // 取消请求缓存，通常用于前后端不分离项目中，方便记录上一个请求地址，进行跳转
            requestCacheConfigurer.disable();

            // 不主动创建 session 来进行缓存
            //HttpSessionRequestCache cache = new HttpSessionRequestCache();
            //cache.setCreateSessionAllowed(false);
            //requestCacheConfigurer.requestCache(cache);
        });

        // 配置鉴权异常拦截器
        http.exceptionHandling(exceptionHandlingConfigurer -> {

            // 未认证，也不是匿名用户，通常是因为 SecurityContext.Authentication 为空，如果 配置 AnonymousConfigurer 就永远不会为空了
            exceptionHandlingConfigurer.authenticationEntryPoint((request, response, authException) -> {
                System.out.println("configure() 认证失败: " + authException.getLocalizedMessage());
                throw new SecurityException("认证失败");
            });

            // 无权限
            exceptionHandlingConfigurer.accessDeniedHandler((request, response, accessDeniedException) -> {
                System.out.println("configure() 无操作权限: " + accessDeniedException.getLocalizedMessage());
                throw new SecurityException("无操作权限");
            });
        });
    }

    /**
     * 自定义异常拦截器
     */
    static class ExceptionFilter extends HttpFilter {

        @Override
        protected void doFilter(HttpServletRequest request, HttpServletResponse response,
                FilterChain chain) throws IOException, ServletException {
            try {
                chain.doFilter(request, response);
            } catch (SecurityException e) {
                returnResult(response, e.getLocalizedMessage());
            }
        }

        private void returnResult(HttpServletResponse response, String result) throws IOException {
            response.setContentType("application/json;charset=utf-8");
            PrintWriter writer = response.getWriter();
            writer.write(new ObjectMapper().writeValueAsString(result));
            writer.flush();
            writer.close();
        }
    }

    /**
     * 日志拦截器
     */
    static class LogFilter extends HttpFilter {

        @Override
        protected void doFilter(HttpServletRequest request, HttpServletResponse response,
                FilterChain chain) throws IOException, ServletException {
            System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>> request start >>>>>>>>>>>>>>>>>>>>>>>>>>>");
            String servletPath = request.getServletPath();
            System.out.println("servletPath: " + servletPath + ", method: " + request.getMethod());

            Map<String, String[]> map = request.getParameterMap();
            for (String key : map.keySet()) {
                String[] values = map.get(key);
                System.out.println("Parameter key: " + key + ", values: " + Arrays.toString(values));
            }

            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    System.out.println("cookie key: " + cookie.getName() + ", value: " + cookie.getValue());
                }
            }

            chain.doFilter(request, response);

            if (!response.isCommitted()) {
                HttpSession session = request.getSession(false);
                if (session != null) {
                    System.out.println("session id: " + session.getId() + ", isNew: " + session.isNew());
                }
            }
            System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>> request end >>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        }
    }

    static abstract class HttpFilter extends GenericFilterBean {

        @Override
        public void doFilter(ServletRequest request, ServletResponse response,
                FilterChain chain) throws IOException, ServletException {
            if (!(request instanceof HttpServletRequest)) {
                throw new ServletException(request + " not HttpServletRequest");
            } else if (!(response instanceof HttpServletResponse)) {
                throw new ServletException(request + " not HttpServletResponse");
            } else {
                this.doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
            }
        }

        protected abstract void doFilter(HttpServletRequest request, HttpServletResponse response,
                FilterChain chain) throws IOException, ServletException;
    }
}
