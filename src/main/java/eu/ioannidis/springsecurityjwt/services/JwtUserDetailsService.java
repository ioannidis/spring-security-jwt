package eu.ioannidis.springsecurityjwt.services;

import eu.ioannidis.springsecurityjwt.models.UserModel;
import eu.ioannidis.springsecurityjwt.models.entities.AuthorityEntity;
import eu.ioannidis.springsecurityjwt.models.entities.UserEntity;
import eu.ioannidis.springsecurityjwt.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class JwtUserDetailsService implements UserDetailsService {

    private UserRepository userRepository;

    @Autowired
    public JwtUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {

        Optional<UserEntity> user = userRepository.findByEmail(s);

        if (user.isEmpty()) {
            throw new UsernameNotFoundException("Invalid email.");
        }

        UserEntity userData = user.get();
        return new UserModel(userData.getId(), userData.getUsername(), userData.getPassword(), userData.getEmail(), userData.getEnabled(), getAuthorities(userData.getAuthorities()));
    }

    // Returns a collection with the granted authorities
    private Collection<GrantedAuthority> getAuthorities(Collection<AuthorityEntity> authorities) {
        return authorities.stream().map(authority -> new SimpleGrantedAuthority(authority.getAuthorityKey().getAuthority())).collect(Collectors.toList());
    }

}
