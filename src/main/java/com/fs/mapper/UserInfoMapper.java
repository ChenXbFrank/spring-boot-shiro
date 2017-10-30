package com.fs.mapper;

import com.fs.entity.UserInfo;

public interface UserInfoMapper {
    /**通过username查找用户信息;*/
    public UserInfo findByUsername(String username);
}