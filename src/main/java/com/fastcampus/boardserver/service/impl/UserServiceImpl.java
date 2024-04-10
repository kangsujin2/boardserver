package com.fastcampus.boardserver.service.impl;

import com.fastcampus.boardserver.dto.UserDTO;
import com.fastcampus.boardserver.exception.DuplicateIdException;
import com.fastcampus.boardserver.mapper.UserProfileMapper;
import com.fastcampus.boardserver.service.UserService;
import com.fastcampus.boardserver.utils.SHA256Util;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@Log4j2
public class UserServiceImpl implements UserService {
  @Autowired private UserProfileMapper userProfileMapper;

  @Override
  public void register(UserDTO userProfile) {
    boolean dupleIdResult = isDuplicatedId(userProfile.getUserId());
    if (dupleIdResult) {
      throw new DuplicateIdException("중복된 아이디입니다.");
    }
    userProfile.setCreateTime(new Date());
    userProfile.setPassword(SHA256Util.encryptSHA256(userProfile.getPassword()));
    int insertCount = userProfileMapper.register(userProfile);

    if (insertCount != 1) {
      log.error("insertMember ERROR! {}", userProfile);
      throw new RuntimeException(
              "insertUser ERROR! 회원가입 메서드를 확인해주세요\n" + "Params : " + userProfile);
    }
  }

  @Override
  public UserDTO login(String id, String password) {
    String cryptoPassword = SHA256Util.encryptSHA256(password);
    UserDTO memberInfo = userProfileMapper.findByUserIdAndPassword(id, cryptoPassword);
    return memberInfo;
  }

  @Override
  public boolean isDuplicatedId(String id) {
    return userProfileMapper.idCheck(id) == 1;
  }

  @Override
  public UserDTO getUserInfo(String userId) {
    return userProfileMapper.getUserProfile(userId);
  }

  @Override
  public void updatePassword(String id, String beforePassword, String afterPassword) {
    String cryptoPassword = SHA256Util.encryptSHA256(beforePassword);
    UserDTO memberInfo = userProfileMapper.findByIdAndPassword(id, cryptoPassword);

    if (memberInfo != null) {
      memberInfo.setPassword(SHA256Util.encryptSHA256(afterPassword));
      int insertCount = userProfileMapper.updatePassword(memberInfo);
    } else {
      log.error("updatePassword ERROR! {}", memberInfo);
      throw new IllegalArgumentException("updatePassword ERROR! 비밀번호 변경 메서드를 확인해주세요\n" + "Params : " + memberInfo);
    }

  }

  @Override
  public void deleteId(String id, String password) {
    String cryptoPassword = SHA256Util.encryptSHA256(password);
    UserDTO memberInfo = userProfileMapper.findByIdAndPassword(id, cryptoPassword);

    if (memberInfo != null) {
      userProfileMapper.deleteUserProfile(memberInfo.getUserId());
    } else {
      log.error("deleteId ERROR! {}", memberInfo);
      throw new RuntimeException("deleteId ERROR! id 삭제 메서드를 확인해주세요\n" + "Params : " + memberInfo);
    }

  }
}
