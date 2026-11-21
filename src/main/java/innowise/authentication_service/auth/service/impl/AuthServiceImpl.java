package innowise.authentication_service.auth.service.impl;

import innowise.authentication_service.auth.client.UserDirectoryClient;
import innowise.authentication_service.auth.exception.UserNotFoundByIdException;
import innowise.authentication_service.auth.model.dto.request.CreateCredentialsDto;
import innowise.authentication_service.auth.model.dto.request.LoginDto;
import innowise.authentication_service.auth.model.dto.request.RefreshTokenDto;
import innowise.authentication_service.auth.model.dto.response.ResponseCredentialsDto;
import innowise.authentication_service.auth.model.dto.response.ResponseTokenPairDto;
import innowise.authentication_service.auth.model.entity.CredentialsEntity;
import innowise.authentication_service.auth.repository.CredentialsRepository;
import innowise.authentication_service.auth.service.AuthService;
import innowise.authentication_service.auth.service.JwtTokenService;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.UUID;

@Service
@Validated
public class AuthServiceImpl implements AuthService {

    private final CredentialsRepository credentialsRepository;
    private final UserDirectoryClient userDirectoryClient;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwtTokenService;
    private final String dummyPasswordHash;

    public AuthServiceImpl(
            CredentialsRepository credentialsRepository,
            UserDirectoryClient userDirectoryClient,
            PasswordEncoder passwordEncoder,
            JwtTokenService jwtTokenService
    ) {
        this.credentialsRepository = credentialsRepository;
        this.userDirectoryClient = userDirectoryClient;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenService = jwtTokenService;
        this.dummyPasswordHash = passwordEncoder.encode(
                UUID.randomUUID().toString()
        );
    }

    @Override
    @Transactional
    public ResponseCredentialsDto saveCredentials(CreateCredentialsDto dto) {
        if (!userDirectoryClient.existsById(dto.userId())) {
            throw new UserNotFoundByIdException(dto.userId());
        }

        if (dto.password().getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new IllegalArgumentException(
                    "Password cannot exceed 72 UTF-8 bytes"
            );
        }

        CredentialsEntity credentials = new CredentialsEntity();
        credentials.setUserId(dto.userId());
        credentials.setLogin(normalizeLogin(dto.login()));
        credentials.setPasswordHash(passwordEncoder.encode(dto.password()));
        credentials.setRole(dto.role());

        CredentialsEntity saved =
                credentialsRepository.saveAndFlush(credentials);

        return new ResponseCredentialsDto(
                saved.getId(),
                saved.getUserId(),
                saved.getLogin(),
                saved.getRole()
        );
    }

    @Override
    @Transactional("authTransactionManager")
    public ResponseTokenPairDto login(LoginDto dto) {
        CredentialsEntity credentials = credentialsRepository
                .findByLoginForUpdate(normalizeLogin(dto.login()))
                .orElse(null);

        String storedHash = credentials == null
                ? dummyPasswordHash
                : credentials.getPasswordHash();

        boolean passwordMatches =
                dto.password().getBytes(StandardCharsets.UTF_8).length <= 72
                        && passwordEncoder.matches(dto.password(), storedHash);

        if (!passwordMatches || credentials == null) {
            throw new BadCredentialsException(
                    "Invalid credentials or token"
            );
        }

        if (!userDirectoryClient.existsByIdAndActiveTrue(credentials.getUserId())) {
            throw new BadCredentialsException(
                    "Invalid credentials or token"
            );
        }

        return issueTokens(credentials);
    }

    @Override
    @Transactional("authTransactionManager")
    public ResponseTokenPairDto refresh(RefreshTokenDto dto) {
        Jwt jwt = jwtTokenService.decodeRefreshToken(dto.refreshToken());
        Long userId = Long.valueOf(jwt.getSubject());

        CredentialsEntity credentials = credentialsRepository
                .findByUserIdForUpdate(userId)
                .orElseThrow(() -> new BadCredentialsException(
                        "Invalid credentials or token"
                ));

        if (!jwtTokenService.matchesRefreshToken(
                dto.refreshToken(),
                credentials.getRefreshTokenHash()
        )
                || !credentials.getRole().name().equals(
                jwt.getClaimAsString("role")
        )
                || !userDirectoryClient.existsByIdAndActiveTrue(userId)) {
            throw new BadCredentialsException(
                    "Invalid credentials or token"
            );
        }

        return issueTokens(credentials);
    }

    private ResponseTokenPairDto issueTokens(CredentialsEntity credentials) {
        ResponseTokenPairDto tokens =
                jwtTokenService.generateTokens(credentials);

        credentials.setRefreshTokenHash(
                jwtTokenService.hashRefreshToken(tokens.refreshToken())
        );

        return tokens;
    }

    private static String normalizeLogin(String login) {
        return login.trim().toLowerCase(Locale.ROOT);
    }
}