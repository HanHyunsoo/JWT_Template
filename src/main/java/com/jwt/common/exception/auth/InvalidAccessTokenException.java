package com.jwt.common.exception.auth;

import com.jwt.common.exception.CustomAbstractException;
import com.jwt.common.response.StatusEnum;

public class InvalidAccessTokenException extends CustomAbstractException {
    public InvalidAccessTokenException() {
        super(StatusEnum.INVALID_ACCESS_TOKEN);
    }
}
