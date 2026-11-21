package innowise.authentication_service.auth;

import innowise.authentication_service.auth.bootstrap.AdminInitializer;
import innowise.authentication_service.auth.config.AdminBootstrapProperties;
import innowise.authentication_service.auth.model.Role;
import innowise.authentication_service.auth.model.dto.request.CreateCredentialsDto;
import innowise.authentication_service.auth.model.entity.CredentialsEntity;
import innowise.authentication_service.auth.repository.CredentialsRepository;
import innowise.authentication_service.auth.service.AdminBootstrapService;
import innowise.authentication_service.auth.service.AuthService;
import innowise.authentication_service.auth.client.UserDirectoryClient;
import innowise.authentication_service.auth.exception.UserDirectoryUnavailableException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.DefaultApplicationArguments;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AdminBootstrapTest {

    private static final String PASSWORD = "bootstrap-test-password";
    private static final CreateCredentialsDto ADMIN = new CreateCredentialsDto(1L, "Admin", PASSWORD, Role.ADMIN);

    @Mock private CredentialsRepository credentials;
    @Mock private UserDirectoryClient users;
    @Mock private AuthService auth;
    @InjectMocks private AdminBootstrapService bootstrap;

    @Test
    void shouldProvisionAdministratorFromStartupProperties() {
        AdminBootstrapProperties properties = new AdminBootstrapProperties(1L, "Admin", PASSWORD);
        when(users.existsByIdAndActiveTrue(1L)).thenReturn(true);

        new AdminInitializer(properties, bootstrap).run(new DefaultApplicationArguments());

        verify(credentials).findByLogin("admin");
        verify(auth).saveCredentials(ADMIN);
        assertThat(properties.toString()).contains("password=***").doesNotContain(PASSWORD);
    }

    @Test
    void shouldKeepExistingAdminCredentialsOnRestart() {
        when(users.existsByIdAndActiveTrue(1L)).thenReturn(true);
        when(credentials.findByUserId(1L)).thenReturn(Optional.of(account(Role.ADMIN, "admin")));

        bootstrap.initialize(ADMIN);

        verifyNoInteractions(auth);
    }

    @ParameterizedTest
    @CsvSource({"USER,admin", "ADMIN,other-login"})
    void shouldRejectDifferentCredentialsForTheSameUser(Role role, String login) {
        when(users.existsByIdAndActiveTrue(1L)).thenReturn(true);
        when(credentials.findByUserId(1L)).thenReturn(Optional.of(account(role, login)));

        assertThatIllegalStateException().isThrownBy(() -> bootstrap.initialize(ADMIN));
        verifyNoInteractions(auth);
    }

    @Test
    void shouldRejectLoginAlreadyAssignedToAnotherUser() {
        when(users.existsByIdAndActiveTrue(1L)).thenReturn(true);
        when(credentials.findByLogin("admin")).thenReturn(Optional.of(account(Role.ADMIN, "admin")));

        assertThatIllegalStateException().isThrownBy(() -> bootstrap.initialize(ADMIN));
        verifyNoInteractions(auth);
    }

    @Test
    void shouldRequireAnActiveBankUser() {
        assertThatIllegalStateException().isThrownBy(() -> bootstrap.initialize(ADMIN));
        verifyNoInteractions(credentials, auth);
    }

    @Test
    void shouldRejectNonAdminRole() {
        CreateCredentialsDto nonAdmin = new CreateCredentialsDto(1L, "Admin", PASSWORD, Role.USER);

        assertThatIllegalArgumentException().isThrownBy(() -> bootstrap.initialize(nonAdmin));
        verifyNoInteractions(users, credentials, auth);
    }

    @Test
    void shouldStopBootstrapWhenUserServiceIsUnavailable() {
        when(users.existsByIdAndActiveTrue(1L)).thenThrow(new UserDirectoryUnavailableException());

        assertThatThrownBy(() -> bootstrap.initialize(ADMIN))
                .isInstanceOf(UserDirectoryUnavailableException.class);

        verifyNoInteractions(credentials, auth);
    }

    private static CredentialsEntity account(Role role, String login) {
        CredentialsEntity account = new CredentialsEntity();
        account.setRole(role);
        account.setLogin(login);
        return account;
    }
}
