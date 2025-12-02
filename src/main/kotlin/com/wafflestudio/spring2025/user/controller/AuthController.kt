package com.wafflestudio.spring2025.user.controller

import com.wafflestudio.spring2025.user.dto.LoginRequest
import com.wafflestudio.spring2025.user.dto.LoginResponse
import com.wafflestudio.spring2025.user.dto.RegisterRequest
import com.wafflestudio.spring2025.user.dto.RegisterResponse
import com.wafflestudio.spring2025.user.service.UserService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.Parameter
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.responses.ApiResponses
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Auth", description = "인증 API")
class AuthController(
    private val userService: UserService,
) {
    @Operation(summary = "회원가입", description = "새로운 사용자를 등록합니다")
    @ApiResponses(
        value = [
            ApiResponse(responseCode = "201", description = "회원가입 성공"),
            ApiResponse(responseCode = "400", description = "잘못된 요청 (username 또는 password가 4자 미만)"),
            ApiResponse(responseCode = "409", description = "이미 존재하는 username"),
        ],
    )
    @PostMapping("/register")
    fun register(
        @RequestBody registerRequest: RegisterRequest,
    ): ResponseEntity<RegisterResponse> {
        val userDto =
            userService.register(
                username = registerRequest.username,
                password = registerRequest.password,
            )
        return ResponseEntity.status(HttpStatus.CREATED).body(userDto)
    }

    @Operation(summary = "로그인", description = "username과 password로 로그인하여 JWT 토큰을 발급받습니다")
    @ApiResponses(
        value = [
            ApiResponse(responseCode = "201", description = "로그인 성공, JWT 토큰 반환"),
            ApiResponse(responseCode = "401", description = "인증 실패 (username 또는 password 불일치)"),
        ],
    )
    @PostMapping("/login")
    fun login(
        @RequestBody loginRequest: LoginRequest,
    ): ResponseEntity<LoginResponse> {
        val token =
            userService.login(
                username = loginRequest.username,
                password = loginRequest.password,
            )
        return ResponseEntity.status(HttpStatus.CREATED).body(LoginResponse(token))
    }

    @Operation(summary = "로그아웃", description = "현재 사용 중인 토큰을 만료(블랙리스트 처리)시킵니다")
    @ApiResponses(
        value = [
            ApiResponse(responseCode = "200", description = "로그아웃 성공"),
        ],
    )
    @PostMapping("/logout")
    fun logout( // 토큰에서 유저 정보를 뽑아옵니다
        @Parameter(hidden = true) @RequestHeader("Authorization") bearerToken: String, // 헤더에서 토큰 문자열을 가져옵니다
    ): ResponseEntity<Unit> {
        // "Bearer " 라는 앞부분을 잘라내고 순수 토큰만 남깁니다.
        if (bearerToken.startsWith("Bearer ")) {
            val token = bearerToken.substring(7)

            // UserService에게 "이 유저, 이 토큰 차단해줘"라고 시킵니다.
            userService.logout(token)
        }

        return ResponseEntity.ok().build()
    }
}
