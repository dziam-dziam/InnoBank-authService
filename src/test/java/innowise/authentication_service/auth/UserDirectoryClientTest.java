package innowise.authentication_service.auth;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import innowise.authentication_service.auth.client.UserDirectoryClient;
import innowise.authentication_service.auth.exception.UserDirectoryUnavailableException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UserDirectoryClientTest {

    private static final String PASSWORD = "test-service-password";

    private final AtomicReference<String> requestedPath = new AtomicReference<>();
    private final AtomicReference<String> authorization = new AtomicReference<>();
    private HttpServer server;
    private UserDirectoryClient client;
    private volatile int responseStatus;
    private volatile String responseBody;

    @BeforeEach
    void startUserServiceStub() throws IOException {
        responseStatus = 200;
        responseBody = "{\"active\":true}";
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/internal/users/", this::respond);
        server.start();
        client = new UserDirectoryClient(baseUrl(), PASSWORD);
    }

    @AfterEach
    void stopUserServiceStub() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void shouldSendUserIdAndAuthenticationServiceCredentials() {
        assertThat(client.existsById(42L)).isTrue();

        assertThat(requestedPath.get()).isEqualTo("/internal/users/42");
        String credentials = Base64.getEncoder().encodeToString(
                ("authentication-service:" + PASSWORD).getBytes(StandardCharsets.ISO_8859_1));
        assertThat(authorization.get()).isEqualTo("Basic " + credentials);
    }

    @Test
    void shouldTreatInactiveProfileAsExisting() {
        responseBody = "{\"active\":false}";

        assertThat(client.existsById(42L)).isTrue();
        assertThat(client.existsByIdAndActiveTrue(42L)).isFalse();
    }

    @Test
    void shouldRecognizeActiveProfile() {
        assertThat(client.existsByIdAndActiveTrue(42L)).isTrue();
    }

    @Test
    void shouldReturnFalseWhenUserDoesNotExist() {
        responseStatus = 404;
        responseBody = "";

        assertThat(client.existsById(42L)).isFalse();
        assertThat(client.existsByIdAndActiveTrue(42L)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(ints = {400, 401, 403, 500, 503})
    void shouldReportDirectoryFailureForOtherHttpErrors(int status) {
        responseStatus = status;
        responseBody = "{}";

        assertThatThrownBy(() -> client.existsById(42L))
                .isInstanceOf(UserDirectoryUnavailableException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "{}", "{\"active\":null}", "{broken"})
    void shouldRejectEmptyOrInvalidResponses(String body) {
        responseBody = body;

        assertThatThrownBy(() -> client.existsById(42L))
                .isInstanceOf(UserDirectoryUnavailableException.class);
    }

    @Test
    void shouldReportDirectoryFailureWhenConnectionIsRefused() {
        server.stop(0);
        server = null;

        assertThatThrownBy(() -> client.existsById(42L))
                .isInstanceOf(UserDirectoryUnavailableException.class);
    }

    @Test
    void shouldRequireServicePassword() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new UserDirectoryClient(baseUrl(), " "));
    }

    private String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private void respond(HttpExchange exchange) throws IOException {
        try (exchange) {
            requestedPath.set(exchange.getRequestURI().getPath());
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            byte[] body = responseBody.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            if (body.length == 0) {
                exchange.sendResponseHeaders(responseStatus, -1);
                return;
            }
            exchange.sendResponseHeaders(responseStatus, body.length);
            exchange.getResponseBody().write(body);
        }
    }
}
