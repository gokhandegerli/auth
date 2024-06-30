package com.degerli.authentication.mapper;

import com.degerli.authentication.model.UserEntity;
import com.degerli.authentication.dto.UserRequest;
import com.degerli.authentication.dto.UserResponse;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface UserMapper {
  @Mapping(target = "role",
      expression = "java(UserEntity.Role.valueOf(userRequest.getRole().toUpperCase()))")
  UserEntity toEntity(UserRequest userRequest);

  @Mapping(target = "role",
      source = "role")
  UserResponse toResponse(UserEntity user);
}