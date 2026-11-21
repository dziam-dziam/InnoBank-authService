package innowise.authentication_service.auth.service;


import innowise.authentication_service.auth.client.UserDirectoryClient;
import innowise.authentication_service.auth.model.Role;
import innowise.authentication_service.auth.model.dto.request.CreateCredentialsDto;
import innowise.authentication_service.auth.model.entity.CredentialsEntity;
import innowise.authentication_service.auth.repository.CredentialsRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;

import java.util.Locale;

@Service
@Validated
@RequiredArgsConstructor
public class AdminBootstrapService {

    private final CredentialsRepository credentialsRepository;
    private final UserDirectoryClient userDirectoryClient;
    private final AuthService authService;

    @Transactional
    public void initialize(@NotNull @Valid CreateCredentialsDto dto) {
        if (dto.role() != Role.ADMIN) {
            throw new IllegalArgumentException(
                    "Bootstrap requires the ADMIN role"
            );
        }

        if (!userDirectoryClient.existsByIdAndActiveTrue(dto.userId())) {
            throw new IllegalStateException(
                    "Bootstrap administrator must reference an existing active user"
            );
        }

        String login = dto.login().toLowerCase(Locale.ROOT);

        CredentialsEntity existing = credentialsRepository
                .findByUserId(dto.userId())
                .orElse(null);

        if (existing != null) {
            if (existing.getRole() != Role.ADMIN
                    || !existing.getLogin().equals(login)) {
                throw new IllegalStateException(
                        "Bootstrap user already has different credentials"
                );
            }

            return;
        }

        if (credentialsRepository.findByLogin(login).isPresent()) {
            throw new IllegalStateException(
                    "Bootstrap login is already assigned to another user"
            );
        }

        authService.saveCredentials(dto);
    }
}