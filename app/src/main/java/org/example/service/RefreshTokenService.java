package org.example.service;


import org.example.entities.RefreshToken;
import org.example.entities.UserInfo;
import org.example.repository.RefreshTokenRepository;
import org.example.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    @Autowired
    RefreshTokenRepository refreshTokenRepository;

    @Autowired
    UserRepository userRepository;

    public RefreshToken createRefreshToken(String username)
    {
        UserInfo userinfo = userRepository.findByUsername(username);
        if(userinfo != null)
        {
            RefreshToken refreshToken = RefreshToken.builder()
                    .userInfo(userinfo)
                    .token(UUID.randomUUID().toString())
                    .expiryDate(Instant.now().plusMillis(600000))
                    .build();

            refreshTokenRepository.save(refreshToken);
            return refreshToken;
        }
        else
            throw new RuntimeException(username+ " user not found ");
    }

    public RefreshToken verifyExpiration(RefreshToken token)
    {
        if(token.getExpiryDate().compareTo(Instant.now()) < 0)
        {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh token is expired, please create new one");
        }
        else
            return token;
    }

    public Optional<RefreshToken> findByToken(String token){
        return refreshTokenRepository.findByToken(token);
    }
}
