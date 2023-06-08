library flutter_secure_storage_web;

import 'dart:convert';
import 'dart:js_util' as js_util;
import 'dart:typed_data';

import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';
import 'package:flutter_secure_storage_web/src/JSDart.dart';
import 'package:flutter_secure_storage_web/src/subtle.dart' as crypto;
import 'package:flutter_web_plugins/flutter_web_plugins.dart';

/// Web implementation of FlutterSecureStorage
class FlutterSecureStorageWeb extends FlutterSecureStoragePlatform {
  static const _publicKey = 'publicKey';

  /// Registrar for FlutterSecureStorageWeb
  static void registerWith(Registrar registrar) {
    FlutterSecureStoragePlatform.instance = FlutterSecureStorageWeb();
  }

  /// Returns true if the storage contains the given [key].
  @override
  Future<bool> containsKey({
    required String key,
    required Map<String, String> options,
  }) =>
      Future.value(
        getLocalStorage().containsKey("${options[_publicKey]!}.$key"),
      );

  /// Deletes associated value for the given [key].
  ///
  /// If the given [key] does not exist, nothing will happen.
  @override
  Future<void> delete({
    required String key,
    required Map<String, String> options,
  }) async {
    getLocalStorage().removeItem("${options[_publicKey]!}.$key");
  }

  /// Deletes all keys with associated values.
  @override
  Future<void> deleteAll({
    required Map<String, String> options,
  }) =>
      Future.sync(
        () => getLocalStorage().clear(),
      );

  /// Encrypts and saves the [key] with the given [value].
  ///
  /// If the key was already in the storage, its associated value is changed.
  /// If the value is null, deletes associated value for the given [key].
  @override
  Future<String?> read({
    required String key,
    required Map<String, String> options,
  }) async {
    final value = getLocalStorage().getItem("${options[_publicKey]!}.$key");
    return _decryptValue(value, options);
  }

  /// Decrypts and returns all keys with associated values.
  @override
  Future<Map<String, String>> readAll({
    required Map<String, String> options,
  }) async {
    final map = <String, String>{};
    final prefix = "${options[_publicKey]!}.";
    for (int j = 0; j < getLocalStorage().length; j++) {
      final key = getLocalStorage().key(j);
      if (key == null) {
        continue;
      }
      if (!key.startsWith(prefix)) {
        continue;
      }
      final value =
          await _decryptValue(getLocalStorage().getItem(key), options);
      if (value == null) {
        continue;
      }

      map[key.substring(prefix.length)] = value;
    }

    return map;
  }

  crypto.Algorithm _getAlgorithm(Uint8List iv) =>
      crypto.Algorithm(name: 'AES-GCM', length: 256, iv: iv);

  Future<JSCryptoKey> _getEncryptionKey(
    crypto.Algorithm algorithm,
    Map<String, String> options,
  ) async {
    late JSCryptoKey encryptionKey;
    final key = options[_publicKey]!;

    if (getLocalStorage().containsKey(key)) {
      final jwk = base64Decode(getLocalStorage().getItem(key)!);

      encryptionKey = await js_util.promiseToFuture<JSCryptoKey>(
        crypto.importKey("raw", jwk, algorithm, false, ["encrypt", "decrypt"]),
      );
    } else {
      //final crypto.getRandomValues(Uint8List(256));

      encryptionKey = await js_util.promiseToFuture<JSCryptoKey>(
        crypto.generateKey(algorithm, true, ["encrypt", "decrypt"]),
      );

      final jsonWebKey = await js_util
          .promiseToFuture<ByteBuffer>(crypto.exportKey("raw", encryptionKey));

      getLocalStorage().setItem(key, base64Encode(jsonWebKey.asUint8List()));
    }

    return encryptionKey;
  }

  /// Encrypts and saves the [key] with the given [value].
  ///
  /// If the key was already in the storage, its associated value is changed.
  /// If the value is null, deletes associated value for the given [key].
  @override
  Future<void> write({
    required String key,
    required String value,
    required Map<String, String> options,
  }) async {
    final iv = getCrypto().getRandomValues(Uint8List(12)).buffer.asUint8List();

    final algorithm = _getAlgorithm(iv);

    final encryptionKey = await _getEncryptionKey(algorithm, options);

    final encryptedContent = await js_util.promiseToFuture<ByteBuffer>(
      crypto.encrypt(
        algorithm,
        encryptionKey,
        Uint8List.fromList(
          utf8.encode(value),
        ),
      ),
    );

    final encoded =
        "${base64Encode(iv)}.${base64Encode(encryptedContent.asUint8List())}";
    getLocalStorage().setItem("${options[_publicKey]!}.$key", encoded);
  }

  Future<String?> _decryptValue(
    String? cypherText,
    Map<String, String> options,
  ) async {
    if (cypherText == null) {
      return null;
    }

    final parts = cypherText.split(".");

    final iv = base64Decode(parts[0]);
    final algorithm = _getAlgorithm(iv);

    final decryptionKey = await _getEncryptionKey(algorithm, options);

    final value = base64Decode(parts[1]);

    final decryptedContent = await js_util.promiseToFuture<ByteBuffer>(
      crypto.decrypt(
        _getAlgorithm(iv),
        decryptionKey,
        Uint8List.fromList(value),
      ),
    );

    final plainText = utf8.decode(decryptedContent.asUint8List());

    return plainText;
  }
}
