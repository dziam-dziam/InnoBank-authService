package innowise.authentication_service.auth.bootstrap;


import innowise.authentication_service.auth.config.AdminBootstrapProperties;
import innowise.authentication_service.auth.model.Role;
import innowise.authentication_service.auth.model.dto.request.CreateCredentialsDto;
import innowise.authentication_service.auth.service.AdminBootstrapService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@EnableConfigurationProperties(AdminBootstrapProperties.class)
@ConditionalOnProperty(
        prefix = "auth.bootstrap-admin",
        name = "enabled",
        havingValue = "true"
)
public class AdminInitializer implements ApplicationRunner {

    private final AdminBootstrapProperties properties;
    private final AdminBootstrapService bootstrapService;

    @Override
    public void run(ApplicationArguments args) {
        bootstrapService.initialize(new CreateCredentialsDto(
                properties.userId(),
                properties.login(),
                properties.password(),
                Role.ADMIN
        ));
    }
}