package org.example.controller;

import lombok.AllArgsConstructor;
import org.example.dto.request.AuthRequestDto;
import org.example.dto.response.JwtResponseDto;
import org.example.dto.request.RefreshTokenRequestDto;
import org.example.entities.RefreshToken;
import org.example.entities.UserInfo;
import org.example.models.UserInfoDto;
import org.example.repository.UserRepository;
import org.example.service.JwtService;
import org.example.service.RefreshTokenService;
import org.example.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@AllArgsConstructor
@RestController
@RequestMapping("/auth/v1")
public class AuthController {


    @Autowired
    private JwtService jwtService;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @PostMapping("/signup")
    public ResponseEntity SignUp(@RequestBody UserInfoDto userInfoDto)
    {
        try{
            UserInfo alreadyExist = userDetailsService.checkIfUserAlreadyExist(userInfoDto);
            if(alreadyExist == null || !alreadyExist.getUsername().equals(userInfoDto.getUsername()))
            {
                String isSignUp = userDetailsService.signupUser(userInfoDto);
                if(isSignUp != null)
                    return new ResponseEntity("user created with id "+isSignUp, HttpStatus.OK);
                else
                    return new ResponseEntity("user not created", HttpStatus.BAD_REQUEST);
            }
            else
                return new ResponseEntity("already user exist", HttpStatus.BAD_REQUEST);
        }
        catch (Exception ex)
        {
            return new ResponseEntity("Exception in user signup service:"+ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/login")
    public ResponseEntity GetToken(@RequestBody AuthRequestDto authRequestDto)
    {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequestDto.getUsername(),authRequestDto.getPassword()));
        if(authentication.isAuthenticated()){
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(authRequestDto.getUsername());
            return new ResponseEntity(JwtResponseDto.builder()
                    .accessToken(jwtService.GenerateToken(authRequestDto.getUsername()))
                    .refreshToken(refreshToken.getToken())
                    .build(), HttpStatus.OK
            );
        }
        else
            return new ResponseEntity("Exception in user service", HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @PostMapping("/refreshToken")
    public JwtResponseDto GetTokenByRefreshToken(@RequestBody RefreshTokenRequestDto refreshTokenRequestDto)
    {
        return refreshTokenService.findByToken(refreshTokenRequestDto.getToken())
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUserInfo)
                .map(userInfo -> {
                    String accessToken = jwtService.GenerateToken(userInfo.getUsername());
                    return JwtResponseDto.builder()
                            .accessToken(accessToken)
                            .refreshToken(refreshTokenRequestDto.getToken())
                            .build();
                }).orElseThrow(()-> new RuntimeException("refresh token is not exist in db"));
    }
}
