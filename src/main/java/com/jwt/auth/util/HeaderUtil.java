package com.jwt.auth.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Arrays;

public class HeaderUtil {

    private final static String HEADER_AUTHORIZATION = "Authorization";
    private final static String TOKEN_PREFIX = "Bearer ";
    private final static String COOKIE_KEY_NAME = "refresh_token";

    /**
     * header에 존재하는 access token을 반환
     *
     * @param request request
     * @return access token or null
     */
    public static String getAccessToken(HttpServletRequest request) {
        String headerValue = request.getHeader(HEADER_AUTHORIZATION);

        if (headerValue == null) {
            return null;
        }

        if (headerValue.startsWith(TOKEN_PREFIX)) {
            return headerValue.substring(TOKEN_PREFIX.length());
        }

        return null;
    }

    /**
     * header에 존재하는 refresh token을 반환
     *
     * @param request request
     * @return refresh token or null
     */
    public static String getRefreshToken(HttpServletRequest request) {
        Cookie cookie = Arrays.stream(request.getCookies())
                .filter(x -> x.getName().equals(COOKIE_KEY_NAME))
                .findFirst()
                .orElse(null);

        if (cookie == null) {
            return null;
        } else {
            return cookie.getValue();
        }
    }

    public static void setRefreshToken(HttpServletResponse response, String refreshToken) {
        Cookie cookie = new Cookie(COOKIE_KEY_NAME, refreshToken);
        // 1시간 뒤 만료
        cookie.setMaxAge(60 * 60);
        // 자바스크립트로 쿠키를 조회하는 것을 막는 옵션
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        // 웹브라우저와 웹서버가 HTTPS로 통신하는 경우에만 웹브라우저가 쿠키를 서버로 전송하는 옵션
//        cookie.setSecure(true);
        response.addCookie(cookie);
    }
}
