package io.security.basicsecurity.security.configs;

import io.security.basicsecurity.security.factory.UrlResourcesMapFactoryBean;
import io.security.basicsecurity.security.filter.PermitAllFilter;
import io.security.basicsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadataSource;
import io.security.basicsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity  // 웹 보안 활성화
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final SecurityResourceService securityResourceService;

    private String[] permitAllResources = {"/", "/login", "user/login/**"};

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http // 인가 정책
                .authorizeRequests()
                .antMatchers("/login").permitAll() // 해당 경로에 대한 모든 접근 허용
                .antMatchers("/user").hasRole("USER") // 해당 경로에 대해 USER 권한이 있는지 인가 심사
                .antMatchers("/admin/pay").access("hasRole('ADMIN')") // access 내부의 표현식에 통과하는지 인가 심사
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();

        http // 인증 정책
                .formLogin()
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response); // 요청 정보가 저장되어 있는 클래스
                        String redirectUrl = savedRequest.getRedirectUrl(); // 인증 전 사용자가 요청했던 url 정보
                        response.sendRedirect(redirectUrl); // 인증에 성공한 상태이므로 원래 가려 했던 url로 redirect
                    }
                });

        http // 로그아웃
                .logout()
                .logoutUrl("/logout")           // 로그아웃 페이지
                .logoutSuccessUrl("/login")     // 로그아웃 후 이동할 페이지
                .addLogoutHandler(new LogoutHandler() { // 로그아웃 핸들러
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();   // 세션 무효화
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() { // 로그아웃 성공 후 핸들러
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember me") // 쿠키 삭제

        .and()
                .rememberMe()
                .rememberMeParameter("remember") // 기본값: remember-me
                .tokenValiditySeconds(3600)      // 기본값: 14일
                .alwaysRemember(false)            // 리멤버 미 기능 항상 실행 (기본값: false)
                .userDetailsService(userDetailsService);  // 리멤버 미 기능 이용 시 인증 계정 조회를 위해 필요

        http // 세션 관리
                .sessionManagement()              // 세션 관리 적용
                .invalidSessionUrl("/invalid")    // 유효하지 않은 세션일 시 이동할 페이지
                .maximumSessions(1)               // 최대 허용 세션 개수
                .maxSessionsPreventsLogin(false)   // 최대 허용 개수 초과 시 정책, false: 기존 세션 만료(default), true: 인증 차단
                .expiredUrl("/expired")           // 세션이 만료된 경우 이동할 페이지
        ;

        http
                .sessionManagement()  // 세션 관리
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 스프링 시큐리티가 필요 시 세션 생성 (default)
        ;


        http
                .exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint() { // 인증 예외 처리
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .accessDeniedHandler(new AccessDeniedHandler() { // 인가 예외 처리
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {

                    }
                })
        ;

        http.addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class);

        return http.build();
        
    }

    @Bean
    public AccessDecisionManager affirmativeBased() {
        AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecisionVoters());
        return affirmativeBased;
    }

    // AccessDecisionManager에 전달될 Voter 목록 반환
    private List<AccessDecisionVoter<?>> getAccessDecisionVoters() {
        List<AccessDecisionVoter<? extends Object>> accessDecisionVoters = new ArrayList<>();
        accessDecisionVoters.add(roleVoter());

        return accessDecisionVoters;
    }

    // RoleHierarchyVoter 생성
    @Bean
    public AccessDecisionVoter<? extends Object> roleVoter() {

        RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter((roleHierarchy()));
        return roleHierarchyVoter;
    }

    // Role Hierarchy를 구성
    @Bean
    public RoleHierarchyImpl roleHierarchy() {

        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        return roleHierarchy;
    }


    @Bean
    public PermitAllFilter customFilterSecurityInterceptor() throws Exception {
        PermitAllFilter permitAllFilter = new PermitAllFilter(permitAllResources);

        permitAllFilter.setSecurityMetadataSource(urlFilterInvocationMetadataSource());
        permitAllFilter.setAccessDecisionManager(affirmativeBased());
        return permitAllFilter;
    }

    @Bean
    public UrlFilterInvocationSecurityMetadataSource urlFilterInvocationMetadataSource() throws Exception {
        return new UrlFilterInvocationSecurityMetadataSource(urlResourcesMapFactoryBean().getObject(), securityResourceService);
    }

    @Bean
    public UrlResourcesMapFactoryBean urlResourcesMapFactoryBean() {
        UrlResourcesMapFactoryBean urlResourcesMapFactoryBean = new UrlResourcesMapFactoryBean();
        urlResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);

        return urlResourcesMapFactoryBean;
    }
}