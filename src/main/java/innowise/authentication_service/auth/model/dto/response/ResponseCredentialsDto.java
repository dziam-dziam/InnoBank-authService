package innowise.authentication_service.auth.model.dto.response;

import innowise.authentication_service.auth.model.Role;

public record ResponseCredentialsDto(
        Long id,
        Long userId,
        String login,
        Role role
) {
}