package eu.ioannidis.springsecurityjwt.models.entities;

import eu.ioannidis.springsecurityjwt.models.entities.embeddalbekeys.AuthorityKey;

import javax.persistence.*;

@Entity
@Table(name = "authorities")
public class AuthorityEntity {

    @EmbeddedId
    private AuthorityKey authorityKey;

    @ManyToOne(fetch = FetchType.EAGER)
    @MapsId("userId")
    private UserEntity user;

    public AuthorityEntity() {
    }

    public AuthorityEntity(AuthorityKey authorityKey, UserEntity user) {
        this.authorityKey = authorityKey;
        this.user = user;
    }

    public AuthorityKey getAuthorityKey() {
        return authorityKey;
    }

    public void setAuthorityKey(AuthorityKey authorityKey) {
        this.authorityKey = authorityKey;
    }

    public UserEntity getUser() {
        return user;
    }

    public void setUser(UserEntity user) {
        this.user = user;
    }

    @Override
    public String toString() {
        return "AuthorityEntity{" +
                "authorityKey=" + authorityKey +
                ", user=" + user +
                '}';
    }
}
