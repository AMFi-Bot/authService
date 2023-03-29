package org.amfibot.auth.discord

import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/auth/discord")
class DiscordOAuth {
    @GetMapping("/redirect")
    fun redirect(): ResponseEntity<*> {
        val headers = HttpHeaders()
        headers.add("Location", "/")
        return ResponseEntity<Any>(headers, HttpStatus.SEE_OTHER)
    }
}