package ru.kata.spring.boot_security.demo.configs;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import ru.kata.spring.boot_security.demo.models.Role;
import ru.kata.spring.boot_security.demo.models.User;
import ru.kata.spring.boot_security.demo.services.RoleService;
import ru.kata.spring.boot_security.demo.services.UserService;

import javax.annotation.PostConstruct;
import java.util.Set;

@Component
public class DataInitializer {

    private final UserService userService;
    private final RoleService roleService;


    @Autowired
    public DataInitializer(UserService userService, RoleService roleService) {
        this.userService = userService;
        this.roleService = roleService;

    }

    @PostConstruct
    public void init() {
        Role roleAdmin = roleService.findByName("ROLE_ADMIN");
        if (roleAdmin == null) {
            roleAdmin = new Role("ROLE_ADMIN");
            roleService.createRole(roleAdmin);
        }

        Role roleUser = roleService.findByName("ROLE_USER");
        if (roleUser == null) {
            roleUser = new Role("ROLE_USER");
            roleService.createRole(roleUser);
        }


        User admin = userService.findByUsername("admin");
        if (admin == null) {
            admin = new User("admin", "admin", Set.of(roleAdmin, roleUser));
            userService.createUser(admin);
        }

        User user = userService.findByUsername("user");
        if (user == null) {
            user = new User("user", "user", Set.of(roleUser));
            userService.createUser(user);
        }
    }
}