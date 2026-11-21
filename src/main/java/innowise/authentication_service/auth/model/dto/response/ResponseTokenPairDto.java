package innowise.authentication_service.auth.model.dto.response;

public record ResponseTokenPairDto(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn
) {
}