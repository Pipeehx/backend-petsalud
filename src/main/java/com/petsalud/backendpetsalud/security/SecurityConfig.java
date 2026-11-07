package cl.petsalud.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Deshabilitar CSRF temporalmente si es API REST stateless (o ajustar según corresponda)
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // Rutas públicas
                        .requestMatchers("/api/public/**", "/login", "/css/**", "/js/**").permitAll()

                        // Rutas exclusivas para CLIENTE
                        .requestMatchers("/api/citas/agendar", "/api/mascotas/mi-historial").hasAnyRole("CLIENTE", "EMPLEADO", "GERENTE")

                        // Rutas para EMPLEADO y GERENTE
                        .requestMatchers(HttpMethod.POST, "/api/expedientes/**").hasAnyRole("EMPLEADO", "GERENTE")
                        .requestMatchers(HttpMethod.PUT, "/api/inventario/**").hasAnyRole("EMPLEADO", "GERENTE")

                        // Rutas exclusivas para GERENTE
                        .requestMatchers("/api/reportes/**", "/api/proveedores/**", "/api/usuarios/**").hasRole("GERENTE")

                        // Cualquier otra solicitud requiere autenticación
                        .anyRequest().authenticated()
                )
                // Configuración de formulario de login por defecto o HTTP Basic
                .formLogin(form -> form
                        .defaultSuccessUrl("/home", true)
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                );

        return http.build();
    }
}