package eu.ioannidis.springsecurityjwt.config.jwt;

import eu.ioannidis.springsecurityjwt.models.UserModel;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtils {

    @Value("${jwt.secret}")
    private String secret;

    // Unix time for token validity
    private static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;

    public String extractSubject(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractUserId(String token) {
        return extractClaim(token).get("uid", String.class);
    }

    public String extractUsername(String token) {
        return extractClaim(token).get("unm", String.class);
    }

    public boolean extractEnabled(String token) {
        return extractClaim(token).get("enb", Boolean.class);
    }

    public String extractAuthorities(String token) {
        return extractClaim(token).get("aut", String.class);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = extractExpiration(token);
        return expiration.before(new Date());
    }

    public String generateToken(UserModel userDetails) {
        return doGenerateToken(userDetails);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractClaim(String token) {
        return extractClaims(token);
    }

    private Claims extractClaims(String token) throws SignatureException {
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    }

    private String doGenerateToken(Map<String, Object> claims, String email) {

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(email)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }

    private String doGenerateToken(UserModel userDetails) {

        HashMap<String, Object> customClaims = new HashMap<>();

        customClaims.put("uid", userDetails.getId().toString());
        customClaims.put("unm", userDetails.getUsername());
        customClaims.put("enb", userDetails.isEnabled());
        customClaims.put("aut", StringUtils.collectionToCommaDelimitedString(userDetails.getAuthorities()));

        return Jwts.builder()
                .setClaims(customClaims)
                .setSubject(userDetails.getEmail())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }

    public Boolean validateToken(String token) throws SignatureException {
        return !isTokenExpired(token);
    }

}
