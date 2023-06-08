import 'dart:typed_data';

import 'package:js/js.dart';

@JS()
@staticInterop
class JSLocalStorage {}

extension JSLocalStorageExtension on JSLocalStorage {
  external String? getItem(String key);

  external void setItem(String key, String value);

  external void removeItem(String key);

  external int get length;

  external String? key(int index);

  external void clear();

  bool containsKey(String key) => getItem(key) != null;
}

@JS()
@staticInterop
class JSCryptoKey {}

extension JSCryptoKeyExtension on JSCryptoKey {
  external Object? get algorithm;

  external bool? get extractable;

  external String? get type;

  external Object? get usages;
}

@JS()
@staticInterop
class JSCrypto {}

extension JSCryptoExtension on JSCrypto {
  external TypedData getRandomValues(List<int> array);
}

@JS('window.localStorage')
external JSLocalStorage getLocalStorage();

@JS('window.crypto')
external JSCrypto getCrypto();
