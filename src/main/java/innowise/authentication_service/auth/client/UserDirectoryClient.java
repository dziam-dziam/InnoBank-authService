
package innowise.authentication_service.auth.client;

import innowise.authentication_service.auth.exception.UserDirectoryUnavailableException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.net.http.HttpClient;
import java.time.Duration;

@Component
public class UserDirectoryClient {

    private final RestClient client;

    public UserDirectoryClient(
            @Value("${services.users.url}") String baseUrl,
            @Value("${services.users.password}") String password
    ) {
        if (password.isBlank()) {
            throw new IllegalArgumentException("Configure a password for User Service");
        }

        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .build();
        JdkClientHttpRequestFactory requests = new JdkClientHttpRequestFactory(httpClient);
        requests.setReadTimeout(Duration.ofSeconds(2));

        client = RestClient.builder()
                .baseUrl(baseUrl)
                .requestFactory(requests)
                .defaultHeaders(headers -> headers.setBasicAuth("authentication-service", password))
                .build();
    }

    public boolean existsById(Long userId) {
        return find(userId) != null;
    }

    public boolean existsByIdAndActiveTrue(Long userId) {
        UserStatus user = find(userId);
        return user != null && user.active();
    }

    private UserStatus find(Long userId) {
        try {
            UserStatus user = client.get()
                    .uri("/internal/users/{id}", userId)
                    .retrieve()
                    .body(UserStatus.class);
            if (user == null || user.active() == null) {
                throw new UserDirectoryUnavailableException();
            }

            return user;
        } catch (HttpClientErrorException.NotFound exception) {
            return null;
        } catch (RestClientException exception) {
            throw new UserDirectoryUnavailableException(exception);
        }
    }

    private record UserStatus(Boolean active) {
    }
}
