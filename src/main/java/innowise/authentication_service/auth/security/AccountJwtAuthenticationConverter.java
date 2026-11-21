package innowise.authentication_service.auth.security;

import innowise.authentication_service.auth.client.UserDirectoryClient;
import innowise.authentication_service.auth.exception.UserDirectoryUnavailableException;
import innowise.authentication_service.auth.model.entity.CredentialsEntity;
import innowise.authentication_service.auth.repository.CredentialsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class AccountJwtAuthenticationConverter
        implements Converter<Jwt, AbstractAuthenticationToken> {

    private final CredentialsRepository credentialsRepository;
    private final UserDirectoryClient users;

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        if (!"access".equals(jwt.getClaimAsString("token_use"))) {
            throw new InvalidBearerTokenException("Invalid access token");
        }

        Long userId = Long.valueOf(jwt.getSubject());

        CredentialsEntity credentials = credentialsRepository
                .findByUserId(userId)
                .orElseThrow(() ->
                        new InvalidBearerTokenException("Invalid access token")
                );

        if (!credentials.getRole().name().equals(jwt.getClaimAsString("role"))
                || !isActive(userId)) {
            throw new InvalidBearerTokenException("Invalid access token");
        }

        SimpleGrantedAuthority authority = new SimpleGrantedAuthority(
                "ROLE_" + credentials.getRole().name()
        );

        return new JwtAuthenticationToken(jwt, List.of(authority));
    }

    private boolean isActive(Long userId) {
        try {
            return users.existsByIdAndActiveTrue(userId);
        } catch (UserDirectoryUnavailableException exception) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("temporarily_unavailable"), exception
            );
        }
    }
}