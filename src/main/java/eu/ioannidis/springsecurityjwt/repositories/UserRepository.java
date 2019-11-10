package eu.ioannidis.springsecurityjwt.repositories;

import eu.ioannidis.springsecurityjwt.models.UserModel;
import eu.ioannidis.springsecurityjwt.models.entities.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<UserEntity, UUID> {
    Optional<UserEntity> findByEmail(String email);
}
