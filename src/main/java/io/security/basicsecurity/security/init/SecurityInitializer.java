package io.security.basicsecurity.security.init;

import io.security.basicsecurity.service.RoleHierarchyService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SecurityInitializer implements ApplicationRunner {

    final private RoleHierarchyService roleHierarchyService;
    final private RoleHierarchyImpl roleHierarchy;

    @Override
    public void run(ApplicationArguments args) {
        // Security가 기동될 때 DB에 저장된 계층 정보를 가져와 반영함
        String allHierarchy = roleHierarchyService.findAllHierarchy();
        roleHierarchy.setHierarchy(allHierarchy);
    }
}