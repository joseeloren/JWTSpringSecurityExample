package es.elrincon.springsecurity.authorization.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import es.elrincon.springsecurity.authorization.entity.RefreshToken;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    void deleteByUsername(String username);
}
