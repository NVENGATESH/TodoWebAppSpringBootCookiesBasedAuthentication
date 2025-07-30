package com.nisahnth.ToDoListWebApp.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
 class CorsConfig  implements WebMvcConfigurer {
  @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
            .allowedOrigins(
                "https://todo-react-app-git-main-nvengateshs-projects.vercel.app",
                "http://localhost:5173"
            )
            .allowedMethods("*")
            .allowCredentials(true);
    }
}
