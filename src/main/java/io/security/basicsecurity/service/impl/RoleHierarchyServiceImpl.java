package io.security.basicsecurity.service.impl;

import io.security.basicsecurity.domain.entity.RoleHierarchy;
import io.security.basicsecurity.repository.RoleHierarchyRepository;
import io.security.basicsecurity.service.RoleHierarchyService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class RoleHierarchyServiceImpl implements RoleHierarchyService {

    final private RoleHierarchyRepository roleHierarchyRepository;

    @Transactional
    @Override
    public String findAllHierarchy() {

        // DB에서 Role 계층 정보를 불러옴
        List<RoleHierarchy> rolesHierarchy = roleHierarchyRepository.findAll();

        StringBuilder concatedRoles = new StringBuilder();

        for (RoleHierarchy model : rolesHierarchy) {
            if (model.getParentName() != null) {
                concatedRoles.append(model.getParentName().getChildName());
                concatedRoles.append(" > ");
                concatedRoles.append(model.getChildName());
                concatedRoles.append("\n");
            }
        }
        return concatedRoles.toString();

    }
}
