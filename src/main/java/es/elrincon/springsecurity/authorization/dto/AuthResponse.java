package es.elrincon.springsecurity.authorization.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String token;
    private String refreshToken;
    private String message;

    public AuthResponse(String token, String refreshToken) {
        this.token = token;
        this.refreshToken = refreshToken;
    }

    public static AuthResponse message(String message) {
        AuthResponse response = new AuthResponse();
        response.setMessage(message);
        return response;
    }
}
