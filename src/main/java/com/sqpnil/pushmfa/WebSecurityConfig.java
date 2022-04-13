package com.sqpnil.pushmfa;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.encrypt.AesBytesEncryptor;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class WebSecurityConfig  {
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .antMatchers("/", "/home").permitAll()
//                .anyRequest().authenticated()
//                .and()
//                .formLogin()
//                .loginPage("/login")
//                .permitAll()
//                .and()
//                .logout()
//                .permitAll();
//    }
//
//    @Bean
//    @Override
//    public UserDetailsService userDetailsService() {
//        UserDetails user =
//                User.withDefaultPasswordEncoder()
//                        .username("user")
//                        .password("password")
//                        .roles("USER")
//                        .build();
//
//        return new InMemoryUserDetailsManager(user);
//    }
//}
//
//

    @Bean
    SecurityFilterChain web(HttpSecurity http,
                            AuthorizationManager<RequestAuthorizationContext> mfaAuthorizationManager) throws Exception {
        MfaAuthenticationHandler mfaAuthenticationHandler = new MfaAuthenticationHandler("/hello");
        // @formatter:off
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .mvcMatchers("/second-factor", "/third-factor","/hello","/hello2").access(mfaAuthorizationManager)
                        .anyRequest().authenticated()
                )
                .formLogin((form) -> form
                        .successHandler(mfaAuthenticationHandler)
                        .failureHandler(mfaAuthenticationHandler)
                )
                .exceptionHandling((exceptions) -> exceptions
                        .withObjectPostProcessor(new ObjectPostProcessor<ExceptionTranslationFilter>() {
                            @Override
                            public <O extends ExceptionTranslationFilter> O postProcess(O filter) {
                                filter.setAuthenticationTrustResolver(new MfaTrustResolver());
                                return filter;
                            }
                        })
                );
        // @formatter:on
        return http.build();
    }

    @Bean
    AuthorizationManager<RequestAuthorizationContext> mfaAuthorizationManager() {
        return (authentication,
                context) -> new AuthorizationDecision(authentication.get() instanceof MfaAuthentication);
    }

    @Bean
    AuthenticationSuccessHandler successHandler() {
        return new SavedRequestAwareAuthenticationSuccessHandler();
    }

    @Bean
    AuthenticationFailureHandler failureHandler() {
        return new SimpleUrlAuthenticationFailureHandler("/login?error");
    }

    @Bean
    MapCustomUserRepository userRepository() {
//        // the hashed password was calculated using the following code
//        // the hash should be done up front, so malicious users cannot discover the
//        // password
//        // PasswordEncoder encoder =
//        // PasswordEncoderFactories.createDelegatingPasswordEncoder();
//        // String encodedPassword = encoder.encode("password");
//
//        // the raw password is "password"
        String encodedPassword = "{bcrypt}$2a$10$h/AJueu7Xt9yh3qYuAXtk.WZJ544Uc2kdOKlHu2qQzCh/A3rq46qm";
//
//        // to sync your phone with the Google Authenticator secret, hand enter the value
//        // in base32Key
//        // String base32Key = "QDWSM3OYBPGTEVSPB5FKVDM3CSNCWHVK";
//        // Base32 base32 = new Base32();
//        // byte[] b = base32.decode(base32Key);
//        // String secret = Hex.encodeHexString(b);
//
        String hexSecret = "80ed266dd80bcd32564f0f4aaa8d9b149a2b1eaa";
//        String encrypted = new String(Hex.encode(encryptor.encrypt(hexSecret.getBytes())));
//
//        // the raw security answer is "smith"
        String encodedSecurityAnswer = "{bcrypt}$2a$10$JIXMjAszy3RUu8y5T0zH0enGJCGumI8YE.K7w3wsM5xXDfeVIsJhq";

        CustomUser customUser = new CustomUser(1L, "swapnil", encodedPassword, hexSecret,
                encodedSecurityAnswer);
        Map<String, CustomUser> emailToCustomUser = new HashMap<>();
        emailToCustomUser.put(customUser.getEmail(), customUser);
        return new MapCustomUserRepository(emailToCustomUser);
    }

    @Bean
    PasswordEncoder encoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
    @Bean
    AesBytesEncryptor encryptor() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        SecretKey key = generator.generateKey();
        return new AesBytesEncryptor(key, KeyGenerators.secureRandom(12), AesBytesEncryptor.CipherAlgorithm.GCM);
    }
}