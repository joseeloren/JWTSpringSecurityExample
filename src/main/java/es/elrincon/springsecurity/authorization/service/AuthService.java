package es.elrincon.springsecurity.authorization.service;

import es.elrincon.springsecurity.authorization.dto.AuthResponse;
import es.elrincon.springsecurity.authorization.entity.RefreshToken;
import es.elrincon.springsecurity.authorization.model.User;
import es.elrincon.springsecurity.authorization.repository.RefreshTokenRepository;
import es.elrincon.springsecurity.authorization.repository.UserRepository;
import es.elrincon.springsecurity.authorization.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;

    public void register(String username, String password) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Usuario ya existe");
        }

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);
    }

    public AuthResponse login(String username, String password) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        String accessToken = jwtService.generateToken(username);
        String refreshToken = createRefreshToken(username);

        return new AuthResponse(accessToken, refreshToken);
    }

    @Transactional
    public AuthResponse refresh(String refreshTokenValue) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenValue)
                .orElseThrow(() -> new IllegalArgumentException("Refresh token no válido"));

        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(refreshToken);
            throw new IllegalArgumentException("Refresh token expirado");
        }

        String newAccessToken = jwtService.generateToken(refreshToken.getUsername());
        return new AuthResponse(newAccessToken, refreshTokenValue);
    }

    @Transactional
    public void logout(String username) {
        refreshTokenRepository.deleteByUsername(username);
    }

    @Transactional
    private String createRefreshToken(String username) {
        // Eliminar refresh tokens antiguos del usuario
        refreshTokenRepository.deleteByUsername(username);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setUsername(username);
        refreshToken.setExpiryDate(Instant.now().plusMillis(jwtService.getRefreshExpiration()));

        refreshTokenRepository.save(refreshToken);
        return refreshToken.getToken();
    }
}
