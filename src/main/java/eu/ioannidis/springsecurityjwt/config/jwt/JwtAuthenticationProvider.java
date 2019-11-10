package eu.ioannidis.springsecurityjwt.config.jwt;

import eu.ioannidis.springsecurityjwt.models.UserModel;
import eu.ioannidis.springsecurityjwt.services.JwtUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;


@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private JwtUserDetailsService jwtUserDetailsService;

    private PasswordEncoder passwordEncoder;

    @Autowired
    public JwtAuthenticationProvider(JwtUserDetailsService jwtUserDetailsService,
                                     PasswordEncoder passwordEncoder) {
        this.jwtUserDetailsService = jwtUserDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        UserModel principal = (UserModel) jwtUserDetailsService.loadUserByUsername(authentication.getName());

        if (!principal.isEnabled()) {
            throw new DisabledException("Account is disabled");
        }

        if (!passwordEncoder.matches(authentication.getCredentials().toString(), principal.getPassword())) {
            throw new BadCredentialsException("Bad credentials");
        }

        return new UsernamePasswordAuthenticationToken(principal,null, principal.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return aClass.equals(UsernamePasswordAuthenticationToken.class);
    }
}
