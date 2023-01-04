package com.jwt.common.exception.auth;

import com.jwt.common.exception.CustomAbstractException;
import com.jwt.common.response.StatusEnum;

public class NotExpiredAccessTokenException extends CustomAbstractException {
    public NotExpiredAccessTokenException() {
        super(StatusEnum.NOT_EXPIRED_ACCESS_TOKEN);
    }
}
