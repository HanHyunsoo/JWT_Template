package com.jwt.common.exception.auth;

import com.jwt.common.exception.CustomAbstractException;
import com.jwt.common.response.StatusEnum;

public class RefreshTokenNotFoundException extends CustomAbstractException {
    public RefreshTokenNotFoundException() {
        super(StatusEnum.REFRESH_TOKEN_NOT_FOUND);
    }
}
