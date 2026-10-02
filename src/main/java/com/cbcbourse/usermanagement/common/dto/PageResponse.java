package com.cbcbourse.usermanagement.common.dto;

import org.springframework.data.domain.Page;

import java.util.List;

/** Représentation JSON stable d'une page de résultats. */
public record PageResponse<T>(
        List<T> content,
        int page,
        int size,
        long totalElements,
        int totalPages
) {
    /**
     * Convertit une {@link Page} Spring Data en réponse JSON stable (page commence à 0).
     * À utiliser dans les modules métier pour que toutes les listes paginées aient le même format.
     */
    public static <T> PageResponse<T> from(Page<T> page) {
        return new PageResponse<>(page.getContent(), page.getNumber(), page.getSize(),
                page.getTotalElements(), page.getTotalPages());
    }
}
