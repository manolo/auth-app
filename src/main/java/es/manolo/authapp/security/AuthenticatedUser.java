package es.manolo.authapp.security;

import java.util.Optional;

import org.springframework.context.annotation.Profile;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.vaadin.flow.router.RouteConfiguration;
import com.vaadin.flow.spring.security.AuthenticationContext;

import es.manolo.authapp.data.User;
import es.manolo.authapp.data.UserRepository;

@Component
@Profile("!control-center")
public class AuthenticatedUser {

    private final UserRepository userRepository;
    protected final AuthenticationContext authenticationContext;

    public AuthenticatedUser(AuthenticationContext authenticationContext, UserRepository userRepository) {
        this.userRepository = userRepository;
        this.authenticationContext = authenticationContext;
    }

    @Transactional
    public Optional<User> get() {
        return authenticationContext.getAuthenticatedUser(UserDetails.class)
                .map(userDetails -> userRepository.findByUsername(userDetails.getUsername()));
    }

    public void logout() {
        authenticationContext.logout();
    }

    public String login() {
        return "login";
    }

    @Component
    @Profile("control-center")
    public static class AuthenticatedUserControlCenter extends AuthenticatedUser {

        public AuthenticatedUserControlCenter(AuthenticationContext authenticationContext, UserRepository userRepository) {
            super(authenticationContext, userRepository);
        }

        @Transactional
        @Override
        public Optional<User> get() {
            RouteConfiguration.forSessionScope().removeRoute("login");
            Object authUser = authenticationContext.getAuthenticatedUser(Object.class).orElse(null);
            if (authUser != null) {
                User user = new User();
                user.setName(authUser.toString().replaceFirst(".*preferred_username=(.*?),.*", "$1"));
                user.setProfilePicture(
                        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
                                .getBytes());
                return Optional.of(user);
            }
            return Optional.empty();
        }

        @Override
        public String login() {
            return "cc-login";
        }
    }

}
