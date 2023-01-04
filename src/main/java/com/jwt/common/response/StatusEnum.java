package com.jwt.common.response;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.*;

@Getter
public enum StatusEnum {
    // 201
    SUCCESS_SIGN_IN(CREATED, "로그인 성공(Access token, Refresh token 발급 성공)"),
    SUCCESS_SIGN_UP(CREATED, "회원가입 성공(Access token, Refresh token 발급 성공)"),
    SUCCESS_REFRESH(CREATED, "Access token refresh 성공"),

    // 400
    NOT_EXPIRED_ACCESS_TOKEN(BAD_REQUEST, "Access token이 만료되지 않았습니다"),

    // 401
    INVALID_ACCESS_TOKEN(UNAUTHORIZED, "Access token이 잘못되었습니다."),
    INVALID_REFRESH_TOKEN(UNAUTHORIZED, "Refresh token이 잘못되었습니다."),
    ACCESS_TOKEN_IS_NULL(UNAUTHORIZED, "Access_token이 존재하지 않습니다."),

    // 403
    EXPIRE_ACCESS_TOKEN(FORBIDDEN, "Access token이 만료되었습니다."),
    EXPIRE_REFRESH_TOKEN(FORBIDDEN, "Refresh token이 만료되었습니다."),
    NO_PERMISSION(FORBIDDEN, "요청한 사용자는 권한이 없습니다."),

    // 404
    USER_NOT_FOUND(NOT_FOUND, "유저를 찾을 수 없음"),
    REFRESH_TOKEN_NOT_FOUND(NOT_FOUND, "Refresh Token DB에 존재하지 않음");

    private final HttpStatus httpStatus;
    private String detail;

    StatusEnum(HttpStatus httpStatus, String detail) {
        this.httpStatus = httpStatus;
        this.detail = detail;
    }

    public StatusEnum setDetail(String detail) {
        this.detail = detail;
        return this;
    }
}
