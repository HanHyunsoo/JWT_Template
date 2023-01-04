package com.jwt.common.exception.auth;

import com.jwt.common.exception.CustomAbstractException;
import com.jwt.common.response.StatusEnum;

public class InvalidRefreshTokenException extends CustomAbstractException {
    public InvalidRefreshTokenException() {
        super(StatusEnum.INVALID_REFRESH_TOKEN);
    }
}
