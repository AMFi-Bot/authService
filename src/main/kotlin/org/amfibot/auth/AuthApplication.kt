package org.amfibot.auth;

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@SpringBootApplication
@RestController
class AuthApplication {


    @GetMapping("/")
    fun root(): String {
        throw Exception("qwertyuy")
//		return "Hello, authentication service!";
    }

}

fun main(args: Array<String>) {
    runApplication<AuthApplication>(*args)
}