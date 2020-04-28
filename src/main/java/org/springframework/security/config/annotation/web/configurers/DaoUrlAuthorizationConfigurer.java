package org.springframework.security.config.annotation.web.configurers;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UrlPathHelper;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import static org.springframework.security.access.vote.AuthenticatedVoter.IS_AUTHENTICATED_FULLY;
import static org.springframework.security.access.vote.AuthenticatedVoter.IS_AUTHENTICATED_REMEMBERED;

/**
 * Created by lb on 2020/4/28.
 * 本来可以直接 继承自 {@link UrlAuthorizationConfigurer} 然后，重写 createMetadataSource() 方法
 * 不过 {@link UrlAuthorizationConfigurer} 是 final 不给继承
 *
 * @see UrlAuthorizationConfigurer
 */

public class DaoUrlAuthorizationConfigurer<H extends HttpSecurityBuilder<H>> extends
        AbstractInterceptUrlConfigurer<DaoUrlAuthorizationConfigurer<H>, H> {

    @Override
    public void configure(H http) throws Exception {
        super.configure(http);
        FilterSecurityInterceptor filterSecurityInterceptor = http.getSharedObject(FilterSecurityInterceptor.class);
        // 不允许 公开调用资源，即资源必须配置权限，即使是匿名权限也需要配置
        filterSecurityInterceptor.setRejectPublicInvocations(true);
    }

    @Override
    FilterInvocationSecurityMetadataSource createMetadataSource(H http) {
        return new DaoFilterInvocationSecurityMetadataSource();
    }

    @Override
    List<AccessDecisionVoter<?>> getDecisionVoters(H http) {
        List<AccessDecisionVoter<?>> decisionVoters = new ArrayList<>();
        RoleVoter rv = new RoleVoter();
        // 取消角色前缀
        //rv.setRolePrefix("");
        decisionVoters.add(rv);
        decisionVoters.add(new AuthenticatedVoter());
        return decisionVoters;
    }

    public static class DaoFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

        // 配置资源角色关系
        String admin = "ROLE_ADMIN";
        String user = "ROLE_USER";
        String anonymous = "ROLE_ANONYMOUS";
        Map<String, Collection<ConfigAttribute>> requestMap = new HashMap<>();

        // 是否检查匿名资源，自动添加其他所有权限
        boolean autoFillAnonymousRole = true;
        private UrlPathHelper urlPathHelper = new UrlPathHelper();

        DaoFilterInvocationSecurityMetadataSource() {
            this(true);
        }

        DaoFilterInvocationSecurityMetadataSource(boolean autoFillAnonymousRole) {
            this.autoFillAnonymousRole = autoFillAnonymousRole;
            // 管理员可以访问
            requestMap.put("/admin/hello", SecurityConfig.createList(admin));
            // 用户和管理员都可以访问
            requestMap.put("/user/hello", SecurityConfig.createList(user, admin));
            // 需要完全认证
            requestMap.put("/fullyAuthenticated", SecurityConfig.createList(IS_AUTHENTICATED_FULLY));
            // 匿名资源，应该配上所有角色
            requestMap.put("/anonymous", SecurityConfig.createList(anonymous));
        }

        @Override
        public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
            final HttpServletRequest request = ((FilterInvocation) object).getRequest();
            Collection<ConfigAttribute> configAttributes = daoQuery(getRequestPath(request));
            if (configAttributes == null) {
                // 用来配置 那些没有资源角色关系的 资源，比如权限放宽到 自动登录
                return SecurityConfig.createList(IS_AUTHENTICATED_REMEMBERED);
            }
            if (!autoFillAnonymousRole) {
                return configAttributes;
            }
            // 检查匿名资源，自动添加其他所有权限
            boolean flag = false;
            for (ConfigAttribute configAttribute : configAttributes) {
                if (anonymous.equals(configAttribute.getAttribute())) {
                    flag = true;
                    break;
                }
            }
            if (flag) {
                Collection<ConfigAttribute> role = daoQueryAllRole();
                configAttributes.addAll(role);
            }
            return configAttributes;
        }

        /**
         * 模拟数据库查询所有角色
         */
        public Collection<ConfigAttribute> daoQueryAllRole() {
            return SecurityConfig.createList(user, admin, anonymous);
        }

        /**
         * 模拟数据库查询资源对应的角色
         */
        public Collection<ConfigAttribute> daoQuery(String requestPath) {
            for (Map.Entry<String, Collection<ConfigAttribute>> entry : requestMap.entrySet()) {
                if (entry.getKey().equals(requestPath)) {
                    return entry.getValue();
                }
            }
            return null;
        }

        private String getRequestPath(HttpServletRequest request) {
            if (this.urlPathHelper != null) {
                return this.urlPathHelper.getPathWithinApplication(request);
            }
            String url = request.getServletPath();
            String pathInfo = request.getPathInfo();
            if (pathInfo != null) {
                url = StringUtils.hasLength(url) ? url + pathInfo : pathInfo;
            }
            return url;
        }

        public Collection<ConfigAttribute> getAllConfigAttributes() {
            Set<ConfigAttribute> allAttributes = new HashSet<>();
            for (Map.Entry<String, Collection<ConfigAttribute>> entry : requestMap.entrySet()) {
                allAttributes.addAll(entry.getValue());
            }
            return allAttributes;
        }

        @Override
        public boolean supports(Class<?> clazz) {
            return FilterInvocation.class.isAssignableFrom(clazz);
        }
    }
}
