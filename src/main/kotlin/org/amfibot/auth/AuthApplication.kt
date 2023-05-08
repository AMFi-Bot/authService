package org.amfibot.auth

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@SpringBootApplication
@RestController
class AuthApplication {


    @GetMapping("/")
    fun root(auth: Authentication): Collection<GrantedAuthority> {
        return auth.authorities
        //return "Welcome to amfi bot authorization service."
    }

}

fun main(args: Array<String>) {
    runApplication<AuthApplication>(*args)
}