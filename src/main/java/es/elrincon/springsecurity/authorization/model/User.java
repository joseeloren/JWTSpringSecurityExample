package es.elrincon.springsecurity.authorization.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    @NotBlank(message = "El usuario no puede estar vacío")
    @Size(min = 3, max = 50, message = "El usuario debe tener entre 3 y 50 caracteres")
    private String username;

    @NotBlank(message = "La contraseña no puede estar vacía")
    private String password;
}
