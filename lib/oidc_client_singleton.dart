import 'package:openid_client/openid_client.dart';
import 'dart:math';
import 'dart:html';
import 'config.dart';

class OIDCClient {
  static OIDCClient? _instance;

  OIDCClient._internal();

  factory OIDCClient.getInstance() {
    _instance ??= OIDCClient._internal();
    return _instance!;
  }

  final String _clientId = Config.clientId;
  final String _clientSecret = Config.clientSecret;
  final Uri _discoveryUri = Uri.parse(Config.keycloakUrl);
  final List<String> _scopes = ['openid', 'profile', 'basic', 'email', 'offline_access'];

  Credential? _credential;

  Future<UserInfo?> getUserInfo() async {
    print("Inside getUserInfo()");
    await _getRedirectResult();
    return _credential?.getUserInfo();
  }

  Future<void> _getRedirectResult() async {
    print("Inside getRedirectResult()");
    final responseUrl = window.sessionStorage["auth_callback_response_url"];

    if (responseUrl != null) {
      final codeVerifier = window.sessionStorage["auth_code_verifier"];
      final state = window.sessionStorage["auth_state"];

      final client = await _getClient();
      final flow = Flow.authorizationCodeWithPKCE(
        client,
        scopes: _scopes,
        codeVerifier: codeVerifier,
        state: state,
      );

      flow.redirectUri = Uri.parse('${window.location.protocol}//${window.location.host}${window.location.pathname}');

      _credential = await flow.callback(Uri.parse(responseUrl).queryParameters);
      print("Inside getRedirectResult(): after credentials: $_credential");
      _cleanupStorage();
      print("cleaned up session storage");
    }
  }

  Future<Client> _getClient() async {
    final issuer = await Issuer.discover(_discoveryUri);
    return Client(issuer, _clientId, clientSecret: _clientSecret);
  }

  String _randomString(int length) {
    final r = Random.secure();
    final chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    return Iterable.generate(length, (_) => chars[r.nextInt(chars.length)]).join();
  }

  void authenticate() async {
    final codeVerifier = _randomString(50);
    final state = _randomString(20);

    final client = await _getClient();
    final flow = Flow.authorizationCodeWithPKCE(
      client,
      scopes: _scopes,
      codeVerifier: codeVerifier,
      state: state,
    );

    flow.redirectUri = Uri.parse('${window.location.protocol}//${window.location.host}${window.location.pathname}');

    window.sessionStorage["auth_code_verifier"] = codeVerifier;
    window.sessionStorage["auth_state"] = state;
    final authorizationUrl = flow.authenticationUri;
    window.location.href = authorizationUrl.toString();
    print("Inside authenticate(): after authorizationCodeWithPKCE");
    throw "Authenticating...";
  }

  Future<void> logOut() async {
    print("Inside logOut");
    final logOutURI = _credential!.generateLogoutUrl().toString();
    _cleanupStorage();
    print("logOutUri in 2nd app: $logOutURI");
    window.open(logOutURI, '_self');
  }

  void _cleanupStorage() {
    window.sessionStorage.remove("auth_code_verifier");
    window.sessionStorage.remove("auth_callback_response_url");
    window.sessionStorage.remove("auth_state");
  }

}