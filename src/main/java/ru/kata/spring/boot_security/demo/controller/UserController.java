package ru.kata.spring.boot_security.demo.controller;


import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import ru.kata.spring.boot_security.demo.models.User;

@Controller
@RequestMapping("/user")
public class UserController {
    @GetMapping()
    public String getUserPage(Model model, @AuthenticationPrincipal User user) {
        model.addAttribute("user", user);

        return "user";
    }
}
