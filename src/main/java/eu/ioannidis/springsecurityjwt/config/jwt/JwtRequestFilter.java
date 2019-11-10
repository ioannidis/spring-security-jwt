package eu.ioannidis.springsecurityjwt.config.jwt;

import eu.ioannidis.springsecurityjwt.models.UserModel;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    private JwtUtils jwtUtils;

    @Autowired
    public JwtRequestFilter(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        final String authentication = httpServletRequest.getHeader("Authentication");

        String token = null;
        Boolean isTokenValid = false;

        // If there is a token and follows the Bearer format
        if (authentication != null) {

            if (authentication.startsWith("Bearer ")) {

                // Remove Bearer prefix
                token = authentication.substring(7);

                try {
                    isTokenValid = jwtUtils.validateToken(token);
                } catch (SignatureException e) {
                    System.out.println("JWT is invalid");
                } catch (ExpiredJwtException e) {
                    System.out.println("JWT Token has expired");
                }
            } else {
                logger.warn("JWT Token does not begin with Bearer String");
            }
        }

        // If subject is null and security context is null
        if (isTokenValid && SecurityContextHolder.getContext().getAuthentication() == null) {

            // If the token is valid, add user to the security context
            if (jwtUtils.validateToken(token)) {

                // Create the principal user
                UserModel principal = new UserModel(
                        UUID.fromString(jwtUtils.extractUserId(token)),
                        jwtUtils.extractUsername(token),
                        "[PROTECTED]",
                        jwtUtils.extractSubject(token),
                        jwtUtils.extractEnabled(token),
                        getGrantedAuthorities(jwtUtils.extractAuthorities(token))
                );

                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());

                usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));

                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }

        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private Collection<? extends GrantedAuthority> getGrantedAuthorities(String authorities) {
        String[] authoritiesList = authorities.split(",");
        return Arrays.stream(authoritiesList).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

}
