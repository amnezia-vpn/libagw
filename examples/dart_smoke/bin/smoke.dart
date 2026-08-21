// Offline Dart FFI smoke test against the c-shared library.
//
//   AGW_BUILDMODE=c-shared scripts/build_archive.sh
//   dart run examples/dart_smoke/bin/smoke.dart build/<goos>_<goarch>/libagw.dylib
//
// Bindings are hand-written here so the example runs with no pub dependencies;
// production code should generate them with ffigen from export/agw.h and use
// package:ffi for the string helpers.
//
// Threading: agw_post blocks for the whole failover sequence. In a Flutter app
// call it from a helper isolate (Isolate.run) so the UI isolate stays live;
// cancel from another isolate via a cancel handle (an int, so it can be sent
// through a SendPort).

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

// ---- ABI types (see export/agw_types.h) ----

final class AgwResult extends Struct {
  @Int32()
  external int code;
  external Pointer<Uint8> body;
  @Size()
  external int bodyLen;
}

typedef AgwLogNative = Void Function(Int32 level, Pointer<Uint8> message, Pointer<Void> userData);
typedef AgwBeforeRequestNative = Void Function(Pointer<Uint8> host, Pointer<Void> userData);

final class AgwCallbacks extends Struct {
  @Size()
  external int structSize;
  external Pointer<NativeFunction<AgwLogNative>> log;
  external Pointer<Void> logUserData;
  external Pointer<NativeFunction<AgwBeforeRequestNative>> onBeforeRequest;
  external Pointer<Void> onBeforeRequestUserData;
}

// ---- string helpers (package:ffi does this for you in real code) ----

Pointer<Uint8> toCString(String s) {
  final bytes = utf8.encode(s);
  final ptr = calloc<Uint8>(bytes.length + 1);
  ptr.asTypedList(bytes.length + 1).setAll(0, [...bytes, 0]);
  return ptr;
}

String fromCString(Pointer<Uint8> ptr) {
  if (ptr == nullptr) return '';
  var len = 0;
  while (ptr[len] != 0) {
    len++;
  }
  return utf8.decode(Uint8List.fromList(ptr.asTypedList(len)));
}

// malloc/free from libc, so the example needs no packages.
final DynamicLibrary _libc = DynamicLibrary.process();
final Pointer<Uint8> Function(int) _malloc =
    _libc.lookupFunction<Pointer<Uint8> Function(Size), Pointer<Uint8> Function(int)>('malloc');
final void Function(Pointer<Uint8>) _free =
    _libc.lookupFunction<Void Function(Pointer<Uint8>), void Function(Pointer<Uint8>)>('free');

Pointer<T> calloc<T extends NativeType>(int count) {
  final p = _malloc(count);
  p.asTypedList(count).fillRange(0, count, 0);
  return p.cast<T>();
}

// ---- library bindings ----

class Agw {
  Agw(this.lib);

  final DynamicLibrary lib;

  late final int Function() abiVersion =
      lib.lookupFunction<Uint32 Function(), int Function()>('agw_abi_version');

  late final int Function(Pointer<Uint8>, Pointer<AgwCallbacks>) clientCreate = lib.lookupFunction<
      UintPtr Function(Pointer<Uint8>, Pointer<AgwCallbacks>),
      int Function(Pointer<Uint8>, Pointer<AgwCallbacks>)>('agw_client_create');

  late final void Function(int) clientDestroy =
      lib.lookupFunction<Void Function(UintPtr), void Function(int)>('agw_client_destroy');

  late final AgwResult Function(int, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, int) post =
      lib.lookupFunction<
          AgwResult Function(UintPtr, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, UintPtr),
          AgwResult Function(int, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, int)>('agw_post');

  late final void Function(Pointer<AgwResult>) resultFree = lib
      .lookupFunction<Void Function(Pointer<AgwResult>), void Function(Pointer<AgwResult>)>(
          'agw_result_free');

  late final int Function() cancelCreate =
      lib.lookupFunction<UintPtr Function(), int Function()>('agw_cancel_create');
  late final void Function(int) cancelCancel =
      lib.lookupFunction<Void Function(UintPtr), void Function(int)>('agw_cancel_cancel');
  late final void Function(int) cancelDestroy =
      lib.lookupFunction<Void Function(UintPtr), void Function(int)>('agw_cancel_destroy');

  late final Pointer<Uint8> Function(int) exportState =
      lib.lookupFunction<Pointer<Uint8> Function(UintPtr), Pointer<Uint8> Function(int)>(
          'agw_export_state');
  late final int Function(int, Pointer<Uint8>) importState =
      lib.lookupFunction<Int32 Function(UintPtr, Pointer<Uint8>), int Function(int, Pointer<Uint8>)>(
          'agw_import_state');
  late final void Function(Pointer<Uint8>) stringFree =
      lib.lookupFunction<Void Function(Pointer<Uint8>), void Function(Pointer<Uint8>)>(
          'agw_string_free');

  late final Pointer<Uint8> Function(int) errorString =
      lib.lookupFunction<Pointer<Uint8> Function(Int32), Pointer<Uint8> Function(int)>(
          'agw_error_string');

  /// Posts one request; frees the native result before returning.
  ({int code, String body}) postJson(int client, String endpoint, String payload,
      {String? options, int cancel = 0}) {
    final cEndpoint = toCString(endpoint);
    final cPayload = toCString(payload);
    final cOptions = options == null ? nullptr as Pointer<Uint8> : toCString(options);
    try {
      final r = post(client, cEndpoint, cPayload, cOptions, cancel);
      final body = fromCString(r.body);
      final holder = calloc<AgwResult>(sizeOf<AgwResult>());
      holder.ref = r;
      resultFree(holder);
      _free(holder.cast<Uint8>());
      return (code: r.code, body: body);
    } finally {
      _free(cEndpoint);
      _free(cPayload);
      if (cOptions != nullptr) _free(cOptions);
    }
  }
}

void expect(bool condition, String what) {
  if (!condition) {
    stderr.writeln('FAIL: $what');
    exit(1);
  }
}

void main(List<String> args) {
  if (args.isEmpty) {
    stderr.writeln('usage: dart run smoke.dart <path to libagw.dylib|.so|.dll>');
    exit(2);
  }

  final agw = Agw(DynamicLibrary.open(args.first));
  expect(agw.abiVersion() == 1, 'abi version is 1');

  // Invalid configs are rejected (handle 0).
  final badConfig = toCString('{}');
  expect(agw.clientCreate(badConfig, nullptr) == 0, 'empty config rejected');
  _free(badConfig);

  final config = toCString(jsonEncode({
    'gateway_endpoint': 'http://127.0.0.1:1',
    'public_key_pem': 'garbage',
    'request_timeout_msecs': 200,
  }));
  final client = agw.clientCreate(config, nullptr);
  _free(config);
  expect(client != 0, 'client created');

  // Offline: envelope build fails with the client-parity code 1105.
  final r = agw.postJson(client, 'v1/services', '{}');
  expect(r.code == 1105, 'missing public key maps to 1105, got ${r.code}');
  expect(fromCString(agw.errorString(1105)).isNotEmpty, 'error string is non-empty');

  // Options are accepted.
  final withOptions = agw.postJson(client, 'v1/services', '{}',
      options: jsonEncode({'service_type': 'svc', 'user_country_code': 'ru'}));
  expect(withOptions.code == 1105, 'options accepted');

  // A pre-cancelled token short-circuits the call.
  final cancel = agw.cancelCreate();
  agw.cancelCancel(cancel);
  expect(agw.postJson(client, 'v1/services', '{}', cancel: cancel).code == 1,
      'cancelled call returns AGW_CANCELLED');
  agw.cancelDestroy(cancel);

  // State round-trip.
  final statePtr = agw.exportState(client);
  final state = fromCString(statePtr);
  agw.stringFree(statePtr);
  expect(jsonDecode(state)['version'] == 1, 'state carries version 1');

  final cState = toCString(state);
  expect(agw.importState(client, cState) == 0, 'state re-imported');
  _free(cState);

  final cJunk = toCString('junk');
  expect(agw.importState(client, cJunk) != 0, 'garbage state rejected');
  _free(cJunk);

  agw.clientDestroy(client);
  stdout.writeln('dart smoke ok');
}
