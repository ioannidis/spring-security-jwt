package eu.ioannidis.springsecurityjwt.controllers;

import eu.ioannidis.springsecurityjwt.config.jwt.JwtResponse;
import eu.ioannidis.springsecurityjwt.config.jwt.JwtUtils;
import eu.ioannidis.springsecurityjwt.models.AuthenticationRequest;
import eu.ioannidis.springsecurityjwt.models.UserModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@CrossOrigin
public class AuthenticationController {

    private AuthenticationManager authenticationManager;

    private JwtUtils jwtUtils;

    @Autowired
    public AuthenticationController(AuthenticationManager authenticationManager,
                                    JwtUtils jwtUtils) {
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
    }

    @GetMapping("/public")
    public ResponseEntity<?> unGuard() {
        return ResponseEntity.ok("hello public");
    }

    @GetMapping("/private")
    public ResponseEntity<?> guard(Authentication p) {
        return ResponseEntity.ok("hello private");
    }

    @GetMapping("/incognito")
    @PreAuthorize("hasAuthority('ROLE_SUPERADMIN')")
    public ResponseEntity<?> sudo(Principal p) {
        return ResponseEntity.ok("hello ROLE_SUPERADMIN");
    }

    @PostMapping("/authenticate")
    public ResponseEntity<JwtResponse>  authenticate(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {

        UserModel user  = (UserModel) authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getEmail(), authenticationRequest.getPassword())).getPrincipal();

        JwtResponse response = new JwtResponse(jwtUtils.generateToken(user));

        return ResponseEntity.ok(response);
    }
}
