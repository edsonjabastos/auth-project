package io.github.edsonjabastos.authserver;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;

import static org.springframework.security.config.Customizer.withDefaults;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
public class SecurityFilterConfig {
    @Bean
    @Order(1)
    SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(withDefaults());
        http.exceptionHandling(
                (exceptions) -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(withDefaults()));

        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated()).formLogin(withDefaults());
        return http.build();
    }
}
