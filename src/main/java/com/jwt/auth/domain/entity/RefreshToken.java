package com.jwt.auth.domain.entity;

import lombok.Builder;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@RedisHash(value = "refreshToken", timeToLive = 60 * 60)
@Builder
public record RefreshToken (@Id String token, String username) {
}
