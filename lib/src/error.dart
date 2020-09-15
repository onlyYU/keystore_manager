part of '../keystore_manager.dart';

class Web3KeychainManagerError extends Error {
  /// 当尝试为一个没有助记词的地址导出助记词时
  static Web3KeychainManagerError errorNotFoundMemories =
      Web3KeychainManagerError(-1, "not found target address's memories.");

  /// 地址对应的keystore文件中，解密出来的地址和当前操作的地址不相同
  static Web3KeychainManagerError errorKeystoreAddressNotEqual =
      Web3KeychainManagerError(-2,
          "keystore file decrypted address is not equal to the current operation address.");

  /// 密码不正确
  static Web3KeychainManagerError errorInvaildPassword =
      Web3KeychainManagerError(-3, "invaild password.");

  /// 缺失了密码字段
  static Web3KeychainManagerError errorMissPassword =
      Web3KeychainManagerError(-4, "miss password.");

  static Web3KeychainManagerError isolateStorageError =
      Web3KeychainManagerError(-5, "call isolate to storage file error.");
  //重复账号
  static Web3KeychainManagerError duplicateAccount = Web3KeychainManagerError(
      -6, "The account you're are trying to import is a duplicate.");

  int _code;
  int get code => this._code;

  String _message;
  String get message => this._message;

  Web3KeychainManagerError(this._code, this._message);
}
