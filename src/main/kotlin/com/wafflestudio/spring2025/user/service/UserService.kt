package com.wafflestudio.spring2025.user.service

import com.wafflestudio.spring2025.user.AuthenticateException
import com.wafflestudio.spring2025.user.JwtTokenProvider
import com.wafflestudio.spring2025.user.SignUpBadPasswordException
import com.wafflestudio.spring2025.user.SignUpBadUsernameException
import com.wafflestudio.spring2025.user.SignUpUsernameConflictException
import com.wafflestudio.spring2025.user.dto.core.UserDto
import com.wafflestudio.spring2025.user.model.User
import com.wafflestudio.spring2025.user.repository.UserRepository
import org.mindrot.jbcrypt.BCrypt
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Service
import java.util.concurrent.TimeUnit

@Service
class UserService(
    private val userRepository: UserRepository,
    private val jwtTokenProvider: JwtTokenProvider,
    private val redisTemplate: StringRedisTemplate,
) {
    fun register(
        username: String,
        password: String,
    ): UserDto {
        if (username.length < 4) {
            throw SignUpBadUsernameException()
        }
        if (password.length < 4) {
            throw SignUpBadPasswordException()
        }

        if (userRepository.existsByUsername(username)) {
            throw SignUpUsernameConflictException()
        }

        val encryptedPassword = BCrypt.hashpw(password, BCrypt.gensalt())
        val user =
            userRepository.save(
                User(
                    username = username,
                    password = encryptedPassword,
                ),
            )
        return UserDto(user)
    }

    fun login(
        username: String,
        password: String,
    ): String {
        val user = userRepository.findByUsername(username) ?: throw AuthenticateException()
        if (BCrypt.checkpw(password, user.password).not()) {
            throw AuthenticateException()
        }
        val accessToken = jwtTokenProvider.createToken(user.username)
        return accessToken
    }

    fun logout(
        token: String,
    ) {
        // 1. 토큰이 유효한지 검사 (이미 만료된 거면 굳이 블랙리스트 넣을 필요 없음)
        if (!jwtTokenProvider.validateToken(token)) {
            return
        }

        // 2. 토큰의 남은 시간 계산
        val expiration = jwtTokenProvider.getRemainingExpiration(token)

        // 3. 남은 시간만큼만 Redis에 "logout" 이라고 저장
        if (expiration > 0) {
            redisTemplate.opsForValue().set(
                token,              // Key: 토큰 값
                "logout",           // Value: 그냥 "logout" 문자열
                expiration,         // Duration: 남은 시간
                TimeUnit.MILLISECONDS // 단위: 밀리초
            )
        }
    }
}
