import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:path_provider/path_provider.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:crypto/crypto.dart';

class MbxSecureFile {
  static const _folderName = 'mbx';
  static const _fileName = 'user_data.mbx';

  /// Save encrypted data (file on Android, Keychain on iOS)
  static Future<void> save(String data, String passphrase, {required String key}) async {
    final encrypted = await _encrypt(data, passphrase);
    final encoded = base64Encode(encrypted);

    if (Platform.isAndroid) {
      final path = await _getPublicDocumentsPath();
      final file = File(path);
      await file.writeAsString(encoded, flush: true);
    } else if (Platform.isIOS) {
      const storage = FlutterSecureStorage();
      await storage.write(key: key, value: encoded);
    } else {
      throw UnsupportedError('Unsupported platform');
    }
  }

  /// Read and decrypt saved data
  static Future<String> read(String passphrase, {required String key}) async {
    String encoded;

    if (Platform.isAndroid) {
      final path = await _getPublicDocumentsPath();
      final file = File(path);
      if (!await file.exists()) {
        throw Exception('Encrypted file not found');
      }
      encoded = await file.readAsString();
    } else if (Platform.isIOS) {
      const storage = FlutterSecureStorage();
      encoded = await storage.read(key: key) ?? '';
      if (encoded.isEmpty) {
        throw Exception('No encrypted data in Keychain');
      }
    } else {
      throw UnsupportedError('Unsupported platform');
    }

    final encryptedBytes = base64Decode(encoded);
    return await _decrypt(encryptedBytes, passphrase);
  }

  /// Encrypt data with AES-256-CBC and PBKDF2
  static Future<Uint8List> _encrypt(String plainText, String passphrase) async {
    final salt = _generateRandomBytes(8);
    final key = await _deriveKey(passphrase, salt);
    final iv = _generateRandomBytes(16);

    final encrypter = encrypt.Encrypter(encrypt.AES(
      encrypt.Key(key),
      mode: encrypt.AESMode.cbc,
      padding: 'PKCS7',
    ));

    final encrypted = encrypter.encrypt(plainText, iv: encrypt.IV(Uint8List.fromList(iv)));
    // Format: [salt][iv][cipherText]
    return Uint8List.fromList([...salt, ...iv, ...encrypted.bytes]);
  }

  /// Decrypt data with AES-256-CBC and PBKDF2
  static Future<Uint8List> _deriveKey(String passphrase, List<int> salt) async {
    final algorithm = Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: 100000,
      bits: 256, // 32 bytes * 8 = 256 bits
    );

    final secretKey = await algorithm.deriveKey(
      secretKey: SecretKey(utf8.encode(passphrase)),
      nonce: salt,
    );

    final keyBytes = await secretKey.extractBytes();
    return Uint8List.fromList(keyBytes);
  }

  /// Derive AES key from passphrase and salt using PBKDF2
  static Future<Uint8List> _deriveKey(String passphrase, List<int> salt) async {
    final pbkdf2 = Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: 100000,
      bits: 256,
    );

    final secretKey = await pbkdf2.deriveKey(
      secretKey: SecretKey(utf8.encode(passphrase)),
      nonce: salt,
    );

    final keyBytes = await secretKey.extractBytes();
    return Uint8List.fromList(keyBytes);
  }
  
  /// Generate secure random bytes
  static List<int> _generateRandomBytes(int length) {
    final rand = Random.secure();
    return List<int>.generate(length, (_) => rand.nextInt(256));
  }

  /// Get public path to /Documents/mbx/user_data.mbx (Android only)
  static Future<String> _getPublicDocumentsPath() async {
    if (Platform.isAndroid) {
      final sdkInt = (await DeviceInfoPlugin().androidInfo).version.sdkInt;

      if (sdkInt >= 30) {
        final status = await Permission.manageExternalStorage.request();
        if (!status.isGranted) {
          throw Exception('Permission denied to access external storage');
        }
      } else {
        final status = await Permission.storage.request();
        if (!status.isGranted) {
          throw Exception('Permission denied to access external storage');
        }
      }

      final dir = Directory('/storage/emulated/0/Documents/$_folderName');
      if (!await dir.exists()) {
        await dir.create(recursive: true);
      }

      return '${dir.path}/$_fileName';
    } else {
      throw UnsupportedError('This platform uses Keychain instead of file storage');
    }
  }
}
