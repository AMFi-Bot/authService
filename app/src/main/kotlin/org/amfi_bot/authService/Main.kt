package org.amfi_bot.authService

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController


@SpringBootApplication
@RestController
class Main {
    @GetMapping("/")
    fun root(): String {
        return "Hello, World!"
    }
}

fun main(args: Array<String>) {
    runApplication<Main>(*args)
}
