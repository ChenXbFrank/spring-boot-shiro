package com.fs.sevice.impl;

import com.fs.entity.UserInfo;
import com.fs.mapper.UserInfoMapper;
import com.fs.sevice.UserInfoService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

@Service
public class UserInfoServiceImpl implements UserInfoService {
    @Resource
    private UserInfoMapper userInfoMapper;
    @Override
    public UserInfo findByUsername(String username) {
        System.out.println("UserInfoServiceImpl.findByUsername()");
        return userInfoMapper.findByUsername(username);
    }
}