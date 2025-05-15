import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:device_info_plus/device_info_plus.dart';

class MbxSecureFile {
  static const _fileName = 'user_data.mbx';
  static const _folderName = 'mbx';

  /// Save encrypted content to file
  static Future<void> saveEncryptedData(String content, String passphrase) async {
    final salt = _generateSalt();
    final iv = _generateIV();
    final key = await _deriveKey(passphrase, salt);
    final encrypted = await _encrypt(content, key, iv);

    final payload = jsonEncode({
      'salt': base64Encode(salt),
      'iv': base64Encode(iv),
      'data': base64Encode(encrypted),
    });

    final filePath = await _getPublicDocumentsPath();
    final file = File(filePath);
    await file.writeAsString(payload);
  }

  /// Read and decrypt content
  static Future<String?> readEncryptedData(String passphrase) async {
    final filePath = await _getPublicDocumentsPath();
    final file = File(filePath);
    if (!await file.exists()) return null;

    final content = await file.readAsString();
    final jsonMap = jsonDecode(content);

    final salt = base64Decode(jsonMap['salt']);
    final iv = base64Decode(jsonMap['iv']);
    final data = base64Decode(jsonMap['data']);

    final key = await _deriveKey(passphrase, salt);
    final decrypted = await _decrypt(data, key, iv);

    return utf8.decode(decrypted);
  }

  /// Derive AES key using PBKDF2 + SHA256
  static Future<Uint8List> _deriveKey(String passphrase, List<int> salt) async {
    final algorithm = Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: 100000,
      bits: 256,
    );
    final secretKey = await algorithm.deriveKey(
      secretKey: SecretKey(utf8.encode(passphrase)),
      nonce: salt,
    );
    final keyBytes = await secretKey.extractBytes();
    return Uint8List.fromList(keyBytes);
  }

  /// AES-256 CBC Encrypt
  static Future<Uint8List> _encrypt(String content, Uint8List key, List<int> iv) async {
    final algorithm = AesCbc.with256bits(macAlgorithm: MacAlgorithm.empty);
    final secretKey = SecretKey(key);
    final secretBox = await algorithm.encrypt(
      utf8.encode(content),
      secretKey: secretKey,
      nonce: iv,
    );
    return Uint8List.fromList(secretBox.cipherText);
  }

  /// AES-256 CBC Decrypt
  static Future<Uint8List> _decrypt(Uint8List data, Uint8List key, List<int> iv) async {
    final algorithm = AesCbc.with256bits(macAlgorithm: MacAlgorithm.empty);
    final secretKey = SecretKey(key);
    final secretBox = SecretBox(data, nonce: iv, mac: Mac.empty);
    final decrypted = await algorithm.decrypt(secretBox, secretKey: secretKey);
    return Uint8List.fromList(decrypted);
  }

  /// Random salt
  static List<int> _generateSalt() => List<int>.generate(16, (_) => _randomByte());

  /// Random IV
  static List<int> _generateIV() => List<int>.generate(16, (_) => _randomByte());

  static int _randomByte() => (255 * (DateTime.now().microsecondsSinceEpoch % 1000) / 1000).floor();

  /// Get file path in Public Documents/mbx/user_data.mbx
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
    } else if (Platform.isIOS) {
      // iOS: Không hỗ trợ file công khai — thay vào đó dùng Keychain nếu cần
      throw UnsupportedError('iOS không hỗ trợ lưu file public. Dùng Keychain thay thế.');
    } else {
      throw UnsupportedError('Unsupported platform');
    }
  }
}