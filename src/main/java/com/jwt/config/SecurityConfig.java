package com.jwt.config;

import com.jwt.auth.filter.JwtAuthenticationFilter;
import com.jwt.auth.handler.CustomAccessDeniedHandler;
import com.jwt.auth.handler.CustomAuthenticationEntryPoint;
import com.jwt.auth.token.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsUtils;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtTokenProvider jwtTokenProvider;
    @Value("${cors.allowed-origins}")
    String[] corsOrigins;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.cors()
                .configurationSource(request -> {
                    var cors = new CorsConfiguration();
                    cors.setAllowedOrigins(List.of(corsOrigins));
                    cors.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
                    cors.setAllowedHeaders(List.of("*"));
                    cors.setExposedHeaders(List.of("Access-Control-Allow-Credentials", "Authorization"));
                    cors.setAllowCredentials(true);
                    return cors;
                });

        return http
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling()
                    .accessDeniedHandler(accessDeniedHandler())
                    .authenticationEntryPoint(authenticationEntryPoint())
                .and()
                .authorizeHttpRequests()
                    .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                    .requestMatchers("/api/auth/*").permitAll()
                    .anyRequest().authenticated()
                .and()
                .build();

    }

    @Bean
    public CustomAccessDeniedHandler accessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }

    @Bean
    public CustomAuthenticationEntryPoint authenticationEntryPoint() {
        return new CustomAuthenticationEntryPoint(jwtTokenProvider);
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtTokenProvider);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

