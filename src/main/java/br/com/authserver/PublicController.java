package br.com.authserver;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("public")
public class PublicController {

    @GetMapping
    public ResponseEntity<String> getPublic() {
        return new ResponseEntity<>("Olá zona publica", HttpStatus.OK);
    }
}
