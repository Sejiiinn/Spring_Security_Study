package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity  // 웹 보안 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http // 인가 정책
                .authorizeRequests()
                .anyRequest().authenticated();

        http // 인증 정책
                .formLogin()
                .defaultSuccessUrl("/");

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
                .alwaysRemember(true)            // 리멤버 미 기능 항상 실행 (기본값: false)
                .userDetailsService(userDetailsService);  // 리멤버 미 기능 이용 시 인증 계정 조회를 위해 필요
    }
}