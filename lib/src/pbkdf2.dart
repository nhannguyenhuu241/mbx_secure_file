import 'dart:typed_data';
import 'package:crypto/crypto.dart';

class PBKDF2 {
  final Hash hashAlgorithm;
  final int iterations;
  final int bits;

  PBKDF2({required this.hashAlgorithm, required this.iterations, required this.bits});

  List<int> process(List<int> password, List<int> salt) {
    final key = pbkdf2(hashAlgorithm, password, salt, iterations, bits ~/ 8);
    return key;
  }
}

List<int> pbkdf2(Hash hash, List<int> password, List<int> salt, int iterations, int keyLength) {
  final hLen = hash.convert([]).bytes.length;
  final l = (keyLength / hLen).ceil();

  var dk = <int>[];

  for (var i = 1; i <= l; i++) {
    var t = _f(hash, password, salt, iterations, i);
    dk.addAll(t);
  }

  return dk.sublist(0, keyLength);
}

List<int> _f(Hash hash, List<int> P, List<int> S, int c, int i) {
  final inti = ByteData(4)..setInt32(0, i, Endian.big);
  var u = <int>[];
  u.addAll(S);
  u.addAll(inti.buffer.asUint8List());

  var result = Hmac(hash, P).convert(u).bytes;
  var T = result;

  for (var j = 1; j < c; j++) {
    result = Hmac(hash, P).convert(result).bytes;
    for (var k = 0; k < T.length; k++) {
      T[k] ^= result[k];
    }
  }

  return T;
}
