package io.security.basicsecurity.security.filter;

import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class PermitAllFilter extends FilterSecurityInterceptor {

    private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";

    private List<RequestMatcher> permitAllRequestMatcher = new ArrayList<>();

    public PermitAllFilter(String... permitAllResources) {
        for (String resource : permitAllResources) {
            permitAllRequestMatcher.add(new AntPathRequestMatcher(resource));
        }
    }

    @Override
    protected InterceptorStatusToken beforeInvocation(Object object) {
        HttpServletRequest request = ((FilterInvocation) object).getRequest();
        for (RequestMatcher requestMatcher : permitAllRequestMatcher) {
            if (requestMatcher.matches(request)) {
                // permit (인가 처리 생략)
                return null;
            }
        }

        // permitAll 에 있지 않은 자원이므로 부모 클래스로 넘어가 인가 처리 진행
        return super.beforeInvocation(object);
    }

    public void invoke(FilterInvocation filterInvocation) throws IOException, ServletException {
        if (isApplied(filterInvocation) && super.isObserveOncePerRequest()) {
            filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
            return;
        }
        if (filterInvocation.getRequest() != null && super.isObserveOncePerRequest()) {
            filterInvocation.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
        }
        // super.beforeInvocation 로 넘어가지 않고 해당 클래스의 beforeInvocation 에서 permitAll 검사
        InterceptorStatusToken token = beforeInvocation(filterInvocation);
        try {
            filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
        } finally {
            super.finallyInvocation(token);
        }
        super.afterInvocation(token, null);
    }

    private boolean isApplied(FilterInvocation filterInvocation) {
        return (filterInvocation.getRequest() != null)
                && (filterInvocation.getRequest().getAttribute(FILTER_APPLIED) != null);
    }
}
