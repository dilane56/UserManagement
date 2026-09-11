package com.cbcbourse.usermanagement.mapper;


import com.cbcbourse.usermanagement.dto.UserRequestDTO;
import com.cbcbourse.usermanagement.dto.UserResponseDTO;
import com.cbcbourse.usermanagement.model.User;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {

    // MapStruct will automatically generate the implementation for this interface at compile time.
    // You can define mapping methods here if needed, for example:

    // Mapping DTO to Entity
    User userResquestDTOToUser(UserRequestDTO request);

    // Mapping Entity to Request DTO
    UserRequestDTO userToUserRequestDTO(User user);

    // Mapping Entity to Response DTO
    UserResponseDTO userToUserResponseDTO(User user);
}
