package es.elrincon.springsecurity.authorization.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

@RestController
@RequestMapping("/api")
public class PlatoController {

    @GetMapping("/platos")
    public List<String> getPlatos() {
        return List.of("Pizza", "Hamburguesa", "Ensalada");
    }
}
