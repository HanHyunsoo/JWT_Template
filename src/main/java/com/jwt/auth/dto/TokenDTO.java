package com.jwt.auth.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Builder;

@Builder
public record TokenDTO(String accessToken, @JsonIgnore String refreshToken) {
}
