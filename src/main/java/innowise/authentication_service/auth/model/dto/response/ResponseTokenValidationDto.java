package innowise.authentication_service.auth.model.dto.response;

import innowise.authentication_service.auth.model.Role;

import java.time.Instant;

public record ResponseTokenValidationDto(boolean valid, Long userId, Role role, Instant expiresAt) {
}