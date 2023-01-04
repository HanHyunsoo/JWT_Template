package com.jwt.auth.token;

import com.jwt.auth.service.CustomUserDetailService;
import com.jwt.auth.util.HeaderUtil;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtTokenProvider {

    private final CustomUserDetailService userDetailService;
    private final SecretKey secretAccessKey;
    private final SecretKey secretRefreshKey;
    // 액세스 토큰 유효시간 10분
    private static final long accessTokenValidTime = 10 * 60 * 1000L;
    // 리프래쉬 토큰 유효시간 1시간
    private static final long refreshTokenValidTime = 60 * 60 * 1000L;

    // access token 생성
    public String createAccessToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        Date now = new Date();

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim("roles", authorities)
                .setExpiration(new Date(now.getTime() + accessTokenValidTime))
                .signWith(secretAccessKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // refresh token 생성
    public String createRandomRefreshToken() {
        Date now = new Date();
        return Jwts.builder()
                .setSubject(UUID.randomUUID().toString())
                .setExpiration(new Date(now.getTime() + refreshTokenValidTime))
                .signWith(secretRefreshKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // JWT 토큰 에서 인증 정보 조회
    public Authentication getAuthentication(String accessToken) {
        UserDetails userDetails = userDetailService.loadUserByUsername(getUsername(accessToken));
        return new UsernamePasswordAuthenticationToken(userDetails, "",
                userDetails.getAuthorities());
    }

    // Request의 Header에서 access token 값을 가져옵니다. "Authorization" : "TOKEN값'
    public String resolveAccessToken(HttpServletRequest request) {
        return HeaderUtil.getAccessToken(request);
    }

    // Request의 Header에서 refresh token 값을 가져옵니다.
    public String resolveRefreshToken(HttpServletRequest request) {
        return HeaderUtil.getRefreshToken(request);
    }

    // access token에서 username 불러오기
    private String getUsername(String accessToken) {
        return Jwts.parserBuilder()
                .setSigningKey(secretAccessKey)
                .build()
                .parseClaimsJws(accessToken)
                .getBody()
                .getSubject();
    }

    // 토큰의 유효성 확인(만료된 토큰도 정상적으로 판단)
    public boolean isValidToken(String token, boolean isAccessToken) {
        Key key = isAccessToken ? secretAccessKey : secretRefreshKey;

        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e);
            return true;
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e);
        }

        return false;
    }

    // 토큰이 정상적인지 확인하고 만료됬는지 확인
    public boolean isExpiredToken(String token, boolean isAccessToken) {
        Key key = isAccessToken ? secretAccessKey : secretRefreshKey;

        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
        } catch (ExpiredJwtException e) {
            return true;
        } catch (Exception ignore) {
        }

        return false;
    }

    public JwtTokenProvider(CustomUserDetailService userDetailService,
                            @Value("${jwt.secret.access}") String secretAccess,
                            @Value("${jwt.secret.refresh}") String secretRefresh) {
        this.userDetailService = userDetailService;
        this.secretAccessKey = Keys.hmacShaKeyFor(secretAccess.getBytes(StandardCharsets.UTF_8));
        this.secretRefreshKey = Keys.hmacShaKeyFor(secretRefresh.getBytes(StandardCharsets.UTF_8));
    }
}
