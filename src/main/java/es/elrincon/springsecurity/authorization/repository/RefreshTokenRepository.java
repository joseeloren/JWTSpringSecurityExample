package es.elrincon.springsecurity.authorization.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import es.elrincon.springsecurity.authorization.entity.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
}
