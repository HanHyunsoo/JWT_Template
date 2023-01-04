package com.jwt.auth.handler;

import com.jwt.auth.token.JwtTokenProvider;
import com.jwt.auth.util.HeaderUtil;
import com.jwt.auth.util.ResponseUtil;
import com.jwt.common.response.StatusEnum;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

@RequiredArgsConstructor
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        String accessToken = HeaderUtil.getAccessToken(request);

        if (accessToken == null) {
            ResponseUtil.setResponse(response, StatusEnum.ACCESS_TOKEN_IS_NULL);
        } else if (!jwtTokenProvider.isValidToken(accessToken, true)) {
            ResponseUtil.setResponse(response, StatusEnum.INVALID_ACCESS_TOKEN);
        } else if (jwtTokenProvider.isExpiredToken(accessToken, true)) {
            ResponseUtil.setResponse(response, StatusEnum.EXPIRE_ACCESS_TOKEN);
        }
    }
}
