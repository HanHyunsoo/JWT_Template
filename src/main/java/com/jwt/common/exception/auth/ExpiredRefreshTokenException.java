package com.jwt.common.exception.auth;

import com.jwt.common.exception.CustomAbstractException;
import com.jwt.common.response.StatusEnum;

public class ExpiredRefreshTokenException extends CustomAbstractException {
    public ExpiredRefreshTokenException() {
        super(StatusEnum.EXPIRE_REFRESH_TOKEN);
    }
}
