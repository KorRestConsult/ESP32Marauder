#include "KorBridge.h"

#ifdef MARAUDER_KOR_BRIDGE

#include "configs.h"

#ifdef MARAUDER_KOR_RPC
#include "KorExpansionRpc.h"
#endif

#include <Arduino.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <WebServer.h>
#include <WebSocketsClient.h>
#include <WiFi.h>
#include <esp_system.h>
#include <mbedtls/md.h>

namespace {

constexpr uint8_t KOR_WIFI_SLOTS = 8;
constexpr uint8_t KOR_NONCE_SLOTS = 8;
constexpr uint8_t KOR_MAX_SAVED_ATTEMPTS = 3;
constexpr uint32_t KOR_WIFI_RETRY_MS = 15000;
constexpr uint32_t KOR_CONNECT_TIMEOUT_MS = 5000;
constexpr uint32_t KOR_APP_HEARTBEAT_MS = 15000;
constexpr uint16_t KOR_DEFAULT_RELAY_PORT = 443;

Preferences prefs;
WebServer provision_server(80);
WebSocketsClient web_socket;

bool bridge_active = false;
bool marauder_busy = false;
bool paused_for_marauder = false;
bool provisioning = false;
bool provision_routes_ready = false;
bool relay_started = false;
bool relay_connected = false;
bool relay_authenticated = false;

uint32_t last_wifi_attempt = 0;
uint32_t last_heartbeat = 0;
uint32_t tx_seq = 0;
uint32_t last_rx_seq = 0;

String device_id;
String boot_nonce;
String auth_token;
String ap_password;

String relay_host;
String relay_path;
String relay_ca;
uint16_t relay_port = KOR_DEFAULT_RELAY_PORT;

String nonce_history[KOR_NONCE_SLOTS];
uint8_t nonce_cursor = 0;

String keyFor(const char* prefix, uint8_t index) {
  return String(prefix) + String(index);
}

String seqToString(uint32_t value) {
  char buf[16];
  snprintf(buf, sizeof(buf), "%lu", (unsigned long)value);
  return String(buf);
}

String randomHex(size_t byte_count) {
  static const char* hex = "0123456789ABCDEF";
  String out;
  out.reserve(byte_count * 2);
  for(size_t i = 0; i < byte_count; ++i) {
    const uint8_t b = (uint8_t)(esp_random() & 0xFF);
    out += hex[(b >> 4) & 0x0F];
    out += hex[b & 0x0F];
  }
  return out;
}

String makeDeviceId() {
  const uint64_t mac = ESP.getEfuseMac();
  char buf[17];
  snprintf(buf, sizeof(buf), "%04X%08X", (uint16_t)(mac >> 32), (uint32_t)mac);
  return String(buf);
}

String ensureToken() {
  prefs.begin("korbridge", false);
  String token = prefs.getString("token", "");
  if(token.length() < 64) {
    token = randomHex(32);
    prefs.putString("token", token);
  }
  prefs.end();
  return token;
}

String ensureApPassword() {
  prefs.begin("korbridge", false);
  String password = prefs.getString("ap_pass", "");
  if(password.length() < 12) {
    password = randomHex(8);
    prefs.putString("ap_pass", password);
  }
  prefs.end();
  return password;
}

String hmacHex(const String& key, const String& message) {
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if(!info) return "";

  uint8_t digest[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);

  if(mbedtls_md_setup(&ctx, info, 1) != 0) {
    mbedtls_md_free(&ctx);
    return "";
  }

  if(mbedtls_md_hmac_starts(
       &ctx,
       reinterpret_cast<const unsigned char*>(key.c_str()),
       key.length()) != 0 ||
     mbedtls_md_hmac_update(
       &ctx,
       reinterpret_cast<const unsigned char*>(message.c_str()),
       message.length()) != 0 ||
     mbedtls_md_hmac_finish(&ctx, digest) != 0) {
    mbedtls_md_free(&ctx);
    return "";
  }

  mbedtls_md_free(&ctx);

  static const char* hex = "0123456789abcdef";
  char out[65];
  for(size_t i = 0; i < sizeof(digest); ++i) {
    out[i * 2] = hex[(digest[i] >> 4) & 0x0F];
    out[i * 2 + 1] = hex[digest[i] & 0x0F];
  }
  out[64] = '\0';
  return String(out);
}

bool secureEqual(const String& a, const String& b) {
  if(a.length() != b.length()) return false;
  uint8_t diff = 0;
  for(size_t i = 0; i < a.length(); ++i) {
    diff |= (uint8_t)(a.charAt(i) ^ b.charAt(i));
  }
  return diff == 0;
}

void sendEnvelope(const char* type, const String& name, const String& payload);\nvoid remoteLog(const String& level, const String& message);\n\n#ifdef MARAUDER_KOR_RPC\n\nbool readProtoVarint(const uint8_t* data, size_t size, size_t& pos, uint64_t& value) {
  value = 0;
  uint8_t shift = 0;

  for(uint8_t i = 0; i < 10 && pos < size; ++i) {
    const uint8_t b = data[pos++];
    value |= ((uint64_t)(b & 0x7F)) << shift;
    if((b & 0x80) == 0) return true;
    shift += 7;
  }

  return false;
}

bool skipProtoField(const uint8_t* data, size_t size, size_t& pos, uint8_t wire_type) {
  uint64_t length = 0;

  switch(wire_type) {
    case 0:
      return readProtoVarint(data, size, pos, length);

    case 1:
      if(size - pos < 8) return false;
      pos += 8;
      return true;

    case 2:
      if(!readProtoVarint(data, size, pos, length)) return false;
      if(length > size - pos) return false;
      pos += (size_t)length;
      return true;

    case 5:
      if(size - pos < 4) return false;
      pos += 4;
      return true;

    default:
      return false;
  }
}

bool allowedReadOnlyRpcTag(uint32_t field) {
  switch(field) {
    case 5:   // system_ping_request
    case 32:  // system_device_info_request
    case 35:  // system_get_datetime_request
    case 39:  // system_protobuf_version_request
    case 44:  // system_power_info_request
    case 28:  // storage_info_request
    case 59:  // storage_timestamp_request
    case 24:  // storage_stat_request
    case 7:   // storage_list_request
    case 9:   // storage_read_request
    case 14:  // storage_md5sum_request
    case 17:  // app_lock_status_request
    case 63:  // app_get_error_request
    case 53:  // gpio_get_pin_mode
    case 55:  // gpio_read_pin
    case 72:  // gpio_get_otg_mode
    case 61:  // property_get_request
    case 66:  // desktop_is_locked_request
      return true;

    default:
      return false;
  }
}

bool validateReadOnlyDelimitedPbMain(const uint8_t* data, size_t size) {
  if(!data || size < 2 || size > 8192) return false;

  size_t pos = 0;
  uint64_t message_size = 0;
  if(!readProtoVarint(data, size, pos, message_size)) return false;
  if(message_size == 0 || message_size > size - pos) return false;

  const size_t message_end = pos + (size_t)message_size;
  if(message_end != size) return false;

  bool found_content = false;

  while(pos < message_end) {
    uint64_t key = 0;
    if(!readProtoVarint(data, message_end, pos, key)) return false;

    const uint32_t field = (uint32_t)(key >> 3);
    const uint8_t wire_type = (uint8_t)(key & 0x07);

    if(field == 0) return false;

    if(field == 3) {
      uint64_t has_next = 0;
      if(wire_type != 0 || !readProtoVarint(data, message_end, pos, has_next)) return false;
      if(has_next != 0) return false;
      continue;
    }

    if(field >= 4) {
      if(found_content || !allowedReadOnlyRpcTag(field)) return false;
      found_content = true;
    }

    if(!skipProtoField(data, message_end, pos, wire_type)) return false;
  }

  return found_content && pos == message_end;
}

String bytesToHex(const uint8_t* data, size_t size) {
  static const char* hex = "0123456789abcdef";
  String out;
  out.reserve(size * 2);

  for(size_t i = 0; i < size; ++i) {
    out += hex[(data[i] >> 4) & 0x0F];
    out += hex[data[i] & 0x0F];
  }

  return out;
}

uint32_t readU32Be(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) |
         ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) |
         (uint32_t)p[3];
}

void writeU32Be(uint8_t* p, uint32_t value) {
  p[0] = (uint8_t)(value >> 24);
  p[1] = (uint8_t)(value >> 16);
  p[2] = (uint8_t)(value >> 8);
  p[3] = (uint8_t)value;
}

bool verifyRpcBinaryEnvelope(
  uint8_t* frame,
  size_t frame_size,
  uint32_t& seq,
  const uint8_t*& protobuf,
  size_t& protobuf_size) {

  if(!relay_authenticated || frame_size < 74) return false;
  if(memcmp(frame, "KRP1", 4) != 0) return false;

  seq = readU32Be(frame + 4);
  protobuf_size = ((size_t)frame[8] << 8) | frame[9];

  if(seq == 0 || seq <= last_rx_seq) return false;
  if(protobuf_size == 0 || protobuf_size > 8192) return false;
  if(frame_size != 10 + protobuf_size + 64) return false;

  protobuf = frame + 10;

  String provided;
  provided.reserve(64);
  for(size_t i = 0; i < 64; ++i) {
    const char ch = (char)frame[10 + protobuf_size + i];
    if(!isxdigit((unsigned char)ch)) return false;
    provided += ch;
  }
  provided.toLowerCase();

  const String canonical =
    device_id + "|" + boot_nonce + "|" + seqToString(seq) +
    "|rpc|" + bytesToHex(protobuf, protobuf_size);

  return secureEqual(hmacHex(auth_token, canonical), provided);
}

void sendRpcBinaryChunk(const uint8_t* data, size_t size) {
  if(!relay_connected || !relay_authenticated || !data || size == 0 || size > 1024) return;

  const uint32_t seq = ++tx_seq;
  const String canonical =
    device_id + "|" + boot_nonce + "|" + seqToString(seq) +
    "|rpc_response|" + bytesToHex(data, size);
  const String mac = hmacHex(auth_token, canonical);
  if(mac.length() != 64) return;

  const size_t frame_size = 10 + size + 64;
  uint8_t* frame = (uint8_t*)malloc(frame_size);
  if(!frame) return;

  memcpy(frame, "KRS1", 4);
  writeU32Be(frame + 4, seq);
  frame[8] = (uint8_t)(size >> 8);
  frame[9] = (uint8_t)size;
  memcpy(frame + 10, data, size);
  memcpy(frame + 10 + size, mac.c_str(), 64);

  web_socket.sendBIN(frame, frame_size);
  free(frame);
}

void handleRelayRpcBinary(uint8_t* frame, size_t frame_size) {
  if(marauder_busy) {
    sendEnvelope("response", "rpc_denied", "{\"error\":\"marauder_busy\"}");
    return;
  }

  uint32_t seq = 0;
  const uint8_t* protobuf = nullptr;
  size_t protobuf_size = 0;

  if(!verifyRpcBinaryEnvelope(frame, frame_size, seq, protobuf, protobuf_size)) {
    remoteLog("warn", "invalid_or_replayed_rpc_frame");
    return;
  }

  if(!validateReadOnlyDelimitedPbMain(protobuf, protobuf_size)) {
    sendEnvelope("response", "rpc_denied", "{\"error\":\"rpc_not_readonly_allowlisted\"}");
    remoteLog("warn", "rpc_request_denied");
    return;
  }

  last_rx_seq = seq;

  if(!KorExpansionRpc::active() && !KorExpansionRpc::open()) {
    sendEnvelope("response", "rpc_unavailable", "{\"error\":\"expansion_uart_unavailable\"}");
    return;
  }

  if(!KorExpansionRpc::sendRequest(protobuf, protobuf_size)) {
    sendEnvelope("response", "rpc_error", "{\"error\":\"expansion_send_failed\"}");
    return;
  }

  sendEnvelope("response", "rpc_accepted", "{\"ok\":true}");
}

void pumpExpansionRpc() {
  if(!KorExpansionRpc::active()) return;

  KorExpansionRpc::loop();

  uint8_t data[256];
  size_t size = 0;
  while((size = KorExpansionRpc::read(data, sizeof(data))) > 0) {
    sendRpcBinaryChunk(data, size);
  }
}

#endif

bool loadWifiProfile(uint8_t index, String& ssid, String& password) {
  if(index >= KOR_WIFI_SLOTS) return false;

  prefs.begin("korbridge", true);
  ssid = prefs.getString(keyFor("s", index).c_str(), "");
  password = prefs.getString(keyFor("p", index).c_str(), "");
  prefs.end();

  return ssid.length() > 0;
}

uint8_t wifiProfileCount() {
  uint8_t count = 0;
  for(uint8_t i = 0; i < KOR_WIFI_SLOTS; ++i) {
    String ssid, password;
    if(loadWifiProfile(i, ssid, password)) ++count;
  }
  return count;
}

bool saveWifiProfile(const String& ssid, const String& password) {
  if(ssid.length() == 0 || ssid.length() > 32 || password.length() > 63) return false;

  int slot = -1;
  for(uint8_t i = 0; i < KOR_WIFI_SLOTS; ++i) {
    String saved, ignored;
    if(loadWifiProfile(i, saved, ignored)) {
      if(saved == ssid) {
        slot = i;
        break;
      }
    } else if(slot < 0) {
      slot = i;
    }
  }

  if(slot < 0) return false;

  prefs.begin("korbridge", false);
  prefs.putString(keyFor("s", slot).c_str(), ssid);
  prefs.putString(keyFor("p", slot).c_str(), password);
  prefs.end();
  return true;
}

bool removeWifiProfile(uint8_t index) {
  if(index >= KOR_WIFI_SLOTS) return false;

  String ssid, password;
  if(!loadWifiProfile(index, ssid, password)) return false;

  prefs.begin("korbridge", false);
  prefs.remove(keyFor("s", index).c_str());
  prefs.remove(keyFor("p", index).c_str());
  prefs.end();
  return true;
}

bool autoOpenAllowed() {
  prefs.begin("korbridge", true);
  const bool allowed = prefs.getBool("allow_open", false);
  prefs.end();
  return allowed;
}

void setAutoOpenAllowed(bool allowed) {
  prefs.begin("korbridge", false);
  prefs.putBool("allow_open", allowed);
  prefs.end();
}

void loadRelayConfig() {
  prefs.begin("korbridge", true);
  relay_host = prefs.getString("relay_host", "");
  relay_path = prefs.getString("relay_path", "/device");
  relay_ca = prefs.getString("relay_ca", "");
  uint32_t stored_port = prefs.getUInt("relay_port", KOR_DEFAULT_RELAY_PORT);
  prefs.end();

  if(stored_port == 0 || stored_port > 65535) stored_port = KOR_DEFAULT_RELAY_PORT;
  relay_port = (uint16_t)stored_port;

  if(relay_path.length() == 0) relay_path = "/device";
  if(relay_path.charAt(0) != '/') relay_path = "/" + relay_path;
}

void saveRelayConfig(const String& host, uint16_t port, const String& path, const String& ca) {
  String normalized_path = path;
  if(normalized_path.length() == 0) normalized_path = "/device";
  if(normalized_path.charAt(0) != '/') normalized_path = "/" + normalized_path;

  prefs.begin("korbridge", false);
  prefs.putString("relay_host", host);
  prefs.putUInt("relay_port", port);
  prefs.putString("relay_path", normalized_path);
  prefs.putString("relay_ca", ca);
  prefs.end();

  loadRelayConfig();
}

bool relayConfigReady() {
  return relay_host.length() > 0 &&
         relay_port > 0 &&
         relay_path.length() > 0 &&
         relay_ca.indexOf("BEGIN CERTIFICATE") >= 0 &&
         auth_token.length() >= 64;
}

bool nonceSeen(const String& nonce) {
  if(nonce.length() < 16 || nonce.length() > 96) return true;
  for(uint8_t i = 0; i < KOR_NONCE_SLOTS; ++i) {
    if(nonce_history[i] == nonce) return true;
  }
  return false;
}

void rememberNonce(const String& nonce) {
  nonce_history[nonce_cursor] = nonce;
  nonce_cursor = (nonce_cursor + 1) % KOR_NONCE_SLOTS;
}

String buildStatusJson() {
  DynamicJsonDocument doc(896);
  doc["firmware"] = MARAUDER_VERSION;
  doc["hardware"] = HARDWARE_NAME;
  doc["bridge_mode"] = bridge_active ? "passive-read-only" : "inactive";
  doc["device"] = device_id.length() ? device_id : makeDeviceId();
  doc["uptime_ms"] = millis();
  doc["heap_free"] = ESP.getFreeHeap();
  doc["wifi_profiles"] = wifiProfileCount();
  doc["auto_open_wifi"] = autoOpenAllowed();
  doc["wifi_connected"] = WiFi.status() == WL_CONNECTED;
  doc["relay_configured"] = relayConfigReady();
  doc["relay_connected"] = relay_connected;
  doc["relay_authenticated"] = relay_authenticated;
  doc["provisioning"] = provisioning;
  doc["marauder_busy"] = marauder_busy;
  #ifdef MARAUDER_KOR_RPC
  doc["rpc"] = KorExpansionRpc::active() ? "experimental-active" : "experimental-ready";
  #else
  doc["rpc"] = "staged-disabled";
  #endif

  if(WiFi.status() == WL_CONNECTED) {
    doc["ssid"] = WiFi.SSID();
    doc["rssi"] = WiFi.RSSI();
    doc["ip"] = WiFi.localIP().toString();
  } else {
    doc["ssid"] = "";
    doc["rssi"] = 0;
    doc["ip"] = "";
  }

  String out;
  serializeJson(doc, out);
  return out;
}

void sendEnvelope(const char* type, const String& name, const String& payload) {
  if(!relay_connected) return;

  const uint32_t seq = ++tx_seq;
  const String nonce = randomHex(12);
  const String canonical =
    device_id + "|" + boot_nonce + "|" + seqToString(seq) + "|" +
    nonce + "|" + String(type) + "|" + name + "|" + payload;

  DynamicJsonDocument doc(2048);
  doc["v"] = 1;
  doc["type"] = type;
  doc["device"] = device_id;
  doc["session"] = boot_nonce;
  doc["seq"] = seq;
  doc["nonce"] = nonce;
  doc["name"] = name;
  doc["payload"] = payload;
  doc["mac"] = hmacHex(auth_token, canonical);

  String out;
  serializeJson(doc, out);
  web_socket.sendTXT(out);
}

void remoteLog(const String& level, const String& message) {
  if(!relay_connected) return;

  DynamicJsonDocument log_doc(512);
  log_doc["level"] = level;
  log_doc["message"] = message;
  log_doc["uptime_ms"] = millis();

  String payload;
  serializeJson(log_doc, payload);
  sendEnvelope("event", "log", payload);
}

bool verifyCommandEnvelope(
  JsonDocument& doc,
  uint32_t& seq,
  String& nonce,
  String& cmd) {

  if((doc["v"] | 0) != 1) return false;
  if(String((const char*)(doc["type"] | "")) != "cmd") return false;
  if(String((const char*)(doc["device"] | "")) != device_id) return false;
  if(String((const char*)(doc["session"] | "")) != boot_nonce) return false;

  seq = doc["seq"] | 0U;
  nonce = String((const char*)(doc["nonce"] | ""));
  cmd = String((const char*)(doc["cmd"] | ""));

  if(seq == 0 || seq <= last_rx_seq) return false;
  if(nonceSeen(nonce)) return false;
  if(cmd.length() == 0 || cmd.length() > 48) return false;

  const String provided = String((const char*)(doc["mac"] | ""));
  if(provided.length() != 64) return false;

  const String canonical =
    device_id + "|" + boot_nonce + "|" + seqToString(seq) + "|" +
    nonce + "|cmd|" + cmd;

  const String expected = hmacHex(auth_token, canonical);
  if(expected.length() != 64 || !secureEqual(expected, provided)) return false;

  return true;
}

void handleRelayText(uint8_t* payload, size_t length) {
  DynamicJsonDocument doc(1024);
  if(deserializeJson(doc, payload, length)) {
    remoteLog("warn", "invalid_json");
    return;
  }

  uint32_t seq = 0;
  String nonce;
  String cmd;

  if(!verifyCommandEnvelope(doc, seq, nonce, cmd)) {
    remoteLog("warn", "invalid_or_replayed_command");
    return;
  }

  last_rx_seq = seq;
  rememberNonce(nonce);
  relay_authenticated = true;

  if(cmd == "status") {
    sendEnvelope("response", "status", buildStatusJson());
    return;
  }

  if(cmd == "ping") {
    sendEnvelope("response", "pong", "{\"ok\":true}");
    return;
  }

  if(cmd == "capabilities") {
    sendEnvelope(
      "response",
      "capabilities",
      "{\"readonly\":true,\"commands\":[\"status\",\"ping\",\"capabilities\"],\"rpc\":\"staged-disabled\"}");
    return;
  }

  sendEnvelope("response", "denied", "{\"error\":\"command_not_allowlisted\"}");
  remoteLog("warn", "denied remote command: " + cmd);
}

void webSocketEvent(WStype_t type, uint8_t* payload, size_t length) {
  switch(type) {
    case WStype_CONNECTED:
      relay_connected = true;
      relay_authenticated = false;
      sendEnvelope("hello", "device", buildStatusJson());
      remoteLog("info", "relay_connected");
      break;

    case WStype_DISCONNECTED:
      relay_connected = false;
      relay_authenticated = false;
      #ifdef MARAUDER_KOR_RPC
      KorExpansionRpc::close();
      #endif
      break;

    case WStype_TEXT:
      handleRelayText(payload, length);
      break;

    case WStype_BIN:
      #ifdef MARAUDER_KOR_RPC
      handleRelayRpcBinary(payload, length);
      #else
      remoteLog("warn", "binary_frame_denied_in_readonly_milestone");
      #endif
      break;

    default:
      break;
  }
}

void stopRelay() {
  #ifdef MARAUDER_KOR_RPC
  KorExpansionRpc::close();
  #endif
  if(relay_started) web_socket.disconnect();
  relay_started = false;
  relay_connected = false;
  relay_authenticated = false;
}

void startRelay() {
  if(relay_started || WiFi.status() != WL_CONNECTED || !relayConfigReady()) return;

  web_socket.onEvent(webSocketEvent);
  web_socket.setReconnectInterval(5000);
  web_socket.enableHeartbeat(15000, 3000, 2);

  // Fail closed: no insecure TLS fallback. A CA certificate must be provisioned.
  web_socket.beginSslWithCA(
    relay_host.c_str(),
    relay_port,
    relay_path.c_str(),
    relay_ca.c_str(),
    "kor-bridge-v1");

  relay_started = true;
}

bool waitForWifi(uint32_t timeout_ms) {
  const uint32_t started = millis();
  while(WiFi.status() != WL_CONNECTED && millis() - started < timeout_ms) {
    delay(100);
  }
  return WiFi.status() == WL_CONNECTED;
}

bool connectSavedWifi() {
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);

  const int found = WiFi.scanNetworks(false, true);
  if(found <= 0) {
    WiFi.scanDelete();
    return false;
  }

  bool attempted[KOR_WIFI_SLOTS] = {false};

  for(uint8_t attempt = 0; attempt < KOR_MAX_SAVED_ATTEMPTS; ++attempt) {
    int best_profile = -1;
    int32_t best_rssi = -1000;

    for(uint8_t profile = 0; profile < KOR_WIFI_SLOTS; ++profile) {
      if(attempted[profile]) continue;

      String ssid, password;
      if(!loadWifiProfile(profile, ssid, password)) continue;

      for(int i = 0; i < found; ++i) {
        if(WiFi.SSID(i) == ssid && WiFi.RSSI(i) > best_rssi) {
          best_profile = profile;
          best_rssi = WiFi.RSSI(i);
        }
      }
    }

    if(best_profile < 0) break;
    attempted[best_profile] = true;

    String ssid, password;
    if(!loadWifiProfile((uint8_t)best_profile, ssid, password)) continue;

    WiFi.disconnect(false, false);
    delay(50);

    if(password.length()) WiFi.begin(ssid.c_str(), password.c_str());
    else WiFi.begin(ssid.c_str());

    if(waitForWifi(KOR_CONNECT_TIMEOUT_MS)) {
      WiFi.scanDelete();
      return true;
    }
  }

  WiFi.scanDelete();
  return false;
}

bool connectBestOpenWifi() {
  if(!autoOpenAllowed()) return false;

  WiFi.mode(WIFI_STA);
  const int count = WiFi.scanNetworks(false, true);
  if(count <= 0) {
    WiFi.scanDelete();
    return false;
  }

  int best = -1;
  int32_t best_rssi = -1000;

  for(int i = 0; i < count; ++i) {
    if(WiFi.encryptionType(i) == WIFI_AUTH_OPEN && WiFi.RSSI(i) > best_rssi) {
      best = i;
      best_rssi = WiFi.RSSI(i);
    }
  }

  if(best < 0) {
    WiFi.scanDelete();
    return false;
  }

  const String ssid = WiFi.SSID(best);
  WiFi.scanDelete();

  WiFi.disconnect(false, false);
  delay(50);
  WiFi.begin(ssid.c_str());
  return waitForWifi(KOR_CONNECT_TIMEOUT_MS);
}

String htmlEscape(const String& input) {
  String out;
  out.reserve(input.length() + 16);

  for(size_t i = 0; i < input.length(); ++i) {
    const char c = input.charAt(i);
    if(c == '&') out += F("&amp;");
    else if(c == '<') out += F("&lt;");
    else if(c == '>') out += F("&gt;");
    else if(c == '"') out += F("&quot;");
    else out += c;
  }

  return out;
}

void prepareProvisionRoutes() {
  if(provision_routes_ready) return;
  provision_routes_ready = true;

  provision_server.on("/", HTTP_GET, []() {
    loadRelayConfig();

    String page;
    page.reserve(5500);
    page += F("<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>");
    page += F("<title>KOR Bridge</title></head><body><h2>KOR Bridge provisioning</h2>");
    page += F("<p>Device: ");
    page += htmlEscape(device_id);
    page += F("</p><form method='POST' action='/save'>");
    page += F("<h3>Wi-Fi</h3><input name='ssid' maxlength='32' placeholder='SSID'><br>");
    page += F("<input name='password' maxlength='63' type='password' placeholder='Password; blank = open network'><br>");
    page += F("<h3>Relay</h3><input name='relay_host' placeholder='relay.example.com' value='");
    page += htmlEscape(relay_host);
    page += F("'><br><input name='relay_port' type='number' value='");
    page += String(relay_port);
    page += F("'><br><input name='relay_path' value='");
    page += htmlEscape(relay_path);
    page += F("'><br><textarea name='relay_ca' rows='12' cols='48' placeholder='PEM CA certificate'>");
    page += htmlEscape(relay_ca);
    page += F("</textarea><br><button type='submit'>Save and reboot bridge</button></form>");
    page += F("<form method='POST' action='/disable'><button type='submit'>Disable KOR Bridge</button></form>");
    page += F("</body></html>");

    provision_server.send(200, "text/html; charset=utf-8", page);
  });

  provision_server.on("/status", HTTP_GET, []() {
    provision_server.send(200, "application/json", buildStatusJson());
  });

  provision_server.on("/save", HTTP_POST, []() {
    bool ok = true;

    const String ssid = provision_server.arg("ssid");
    const String password = provision_server.arg("password");
    if(ssid.length()) ok = saveWifiProfile(ssid, password);

    const String host = provision_server.arg("relay_host");
    const String path = provision_server.arg("relay_path");
    const String ca = provision_server.arg("relay_ca");
    long port_value = provision_server.arg("relay_port").toInt();

    if(host.length() || ca.length()) {
      if(host.length() == 0 ||
         ca.indexOf("BEGIN CERTIFICATE") < 0 ||
         port_value <= 0 ||
         port_value > 65535) {
        ok = false;
      } else {
        saveRelayConfig(host, (uint16_t)port_value, path, ca);
      }
    }

    provision_server.send(
      ok ? 200 : 400,
      "text/plain",
      ok ? "Saved. ESP32 is rebooting." : "Invalid settings.");

    if(ok) {
      delay(400);
      ESP.restart();
    }
  });

  provision_server.on("/disable", HTTP_POST, []() {
    prefs.begin("korbridge", false);
    prefs.putBool("enabled", false);
    prefs.end();

    provision_server.send(200, "text/plain", "KOR Bridge disabled. ESP32 is rebooting.");
    delay(400);
    ESP.restart();
  });
}

void startProvisioning() {
  if(provisioning || marauder_busy) return;

  stopRelay();

  provisioning = true;
  ap_password = ensureApPassword();

  WiFi.disconnect(false, false);
  delay(50);
  WiFi.mode(WIFI_AP);

  const String suffix = device_id.substring(device_id.length() > 6 ? device_id.length() - 6 : 0);
  const String ssid = "KOR-Setup-" + suffix;

  WiFi.softAP(ssid.c_str(), ap_password.c_str());

  prepareProvisionRoutes();
  provision_server.begin();

  Serial.print(F("@KOR provisioning AP: "));
  Serial.println(ssid);
  Serial.print(F("@KOR provisioning password: "));
  Serial.println(ap_password);
  Serial.println(F("@KOR provisioning URL: http://192.168.4.1/"));
}

void stopProvisioning() {
  if(!provisioning) return;

  provision_server.stop();
  WiFi.softAPdisconnect(true);
  provisioning = false;
  WiFi.mode(WIFI_STA);
}

void tryNetworkAndRelay() {
  if(marauder_busy) return;

  if(WiFi.status() != WL_CONNECTED) {
    if(relay_started) stopRelay();

    if(!connectSavedWifi() && !connectBestOpenWifi()) {
      startProvisioning();
      return;
    }
  }

  if(!relayConfigReady()) {
    startProvisioning();
    return;
  }

  if(provisioning) stopProvisioning();
  startRelay();
}

void printStatus() {
  Serial.println(buildStatusJson());
}

}  // namespace

bool KorBridge::enabled() {
  prefs.begin("korbridge", true);
  const bool value = prefs.getBool("enabled", false);
  prefs.end();
  return value;
}

void KorBridge::begin() {
  device_id = makeDeviceId();
  boot_nonce = randomHex(16);
  auth_token = ensureToken();
  ap_password = ensureApPassword();
  loadRelayConfig();

  bridge_active = enabled();
  if(!bridge_active) return;

  #ifdef MARAUDER_KOR_RPC
  KorExpansionRpc::begin();
  #endif

  WiFi.persistent(false);
  WiFi.setAutoReconnect(true);

  Serial.println(F("@KOR bridge enabled: PASSIVE/READ-ONLY"));
  tryNetworkAndRelay();
}

void KorBridge::loop(bool marauderBusy) {
  if(!bridge_active) return;

  marauder_busy = marauderBusy;

  if(marauder_busy) {
    #ifdef MARAUDER_KOR_RPC
    KorExpansionRpc::close();
    #endif
    if(!paused_for_marauder) {
      paused_for_marauder = true;
      stopRelay();
      stopProvisioning();
      WiFi.disconnect(false, false);
      Serial.println(F("@KOR paused: Marauder active"));
    }
    return;
  }

  if(paused_for_marauder) {
    paused_for_marauder = false;
    last_wifi_attempt = 0;
    Serial.println(F("@KOR resumed"));
  }

  if(provisioning) {
    provision_server.handleClient();
    delay(1);
    return;
  }

  if(WiFi.status() != WL_CONNECTED) {
    if(millis() - last_wifi_attempt >= KOR_WIFI_RETRY_MS) {
      last_wifi_attempt = millis();
      tryNetworkAndRelay();
    }
    delay(1);
    return;
  }

  if(!relayConfigReady()) {
    startProvisioning();
    delay(1);
    return;
  }

  if(!relay_started) startRelay();
  if(relay_started) web_socket.loop();

  #ifdef MARAUDER_KOR_RPC
  if(relay_connected && relay_authenticated) pumpExpansionRpc();
  #endif

  if(relay_connected && millis() - last_heartbeat >= KOR_APP_HEARTBEAT_MS) {
    last_heartbeat = millis();
    sendEnvelope("event", "heartbeat", buildStatusJson());
  }

  delay(1);
}

bool KorBridge::ownsUart() {
  #ifdef MARAUDER_KOR_RPC
  return KorExpansionRpc::ownsUart();
  #else
  return false;
  #endif
}

String KorBridge::statusJson() {
  return buildStatusJson();
}

bool KorBridge::handleCli(LinkedList<String>& args) {
  if(args.size() == 0 || args.get(0) != "kor") return false;

  if(args.size() == 1 || args.get(1) == "help") {
    Serial.println(F("kor status"));
    Serial.println(F("kor identity"));
    Serial.println(F("kor bridge on|off"));
    Serial.println(F("kor wifi list"));
    Serial.println(F("kor wifi add <ssid> [password]"));
    Serial.println(F("kor wifi remove <index>"));
    Serial.println(F("kor wifi auto-open on|off"));
    Serial.println(F("kor relay show"));
    Serial.println(F("kor relay set <host> <port> <path>"));
    Serial.println(F("kor provision"));
    Serial.println(F("kor token <value>"));
    return true;
  }

  const String sub = args.get(1);

  if(sub == "status") {
    printStatus();
    return true;
  }

  if(sub == "identity") {
    Serial.print(F("device="));
    Serial.println(device_id.length() ? device_id : makeDeviceId());
    Serial.print(F("token="));
    Serial.println(auth_token.length() ? auth_token : ensureToken());
    return true;
  }

  if(sub == "bridge" && args.size() >= 3) {
    const bool on = args.get(2) == "on";
    const bool off = args.get(2) == "off";

    if(!on && !off) {
      Serial.println(F("ERR: use on|off"));
      return true;
    }

    prefs.begin("korbridge", false);
    prefs.putBool("enabled", on);
    prefs.end();

    Serial.println(on ? F("KOR Bridge enabled; rebooting ESP32") : F("KOR Bridge disabled; rebooting ESP32"));
    delay(250);
    ESP.restart();
    return true;
  }

  if(sub == "wifi" && args.size() >= 3) {
    const String action = args.get(2);

    if(action == "list") {
      for(uint8_t i = 0; i < KOR_WIFI_SLOTS; ++i) {
        String ssid, password;
        if(loadWifiProfile(i, ssid, password)) {
          Serial.print(i);
          Serial.print(F(": "));
          Serial.print(ssid);
          Serial.println(password.length() ? F(" [secured]") : F(" [open]"));
        }
      }
      return true;
    }

    if(action == "add" && args.size() >= 4) {
      const String ssid = args.get(3);
      const String password = args.size() >= 5 ? args.get(4) : "";
      Serial.println(saveWifiProfile(ssid, password) ? F("OK") : F("ERR"));
      return true;
    }

    if(action == "remove" && args.size() >= 4) {
      const int idx = args.get(3).toInt();
      if(idx < 0 || idx >= KOR_WIFI_SLOTS) {
        Serial.println(F("ERR"));
        return true;
      }
      Serial.println(removeWifiProfile((uint8_t)idx) ? F("OK") : F("ERR"));
      return true;
    }

    if(action == "auto-open" && args.size() >= 4) {
      if(args.get(3) == "on") setAutoOpenAllowed(true);
      else if(args.get(3) == "off") setAutoOpenAllowed(false);
      else {
        Serial.println(F("ERR: use on|off"));
        return true;
      }

      Serial.println(F("OK"));
      return true;
    }
  }

  if(sub == "relay" && args.size() >= 3) {
    const String action = args.get(2);

    if(action == "show") {
      loadRelayConfig();

      Serial.print(F("host="));
      Serial.println(relay_host);
      Serial.print(F("port="));
      Serial.println(relay_port);
      Serial.print(F("path="));
      Serial.println(relay_path);
      Serial.print(F("ca_set="));
      Serial.println(relay_ca.indexOf("BEGIN CERTIFICATE") >= 0 ? F("yes") : F("no"));
      Serial.print(F("connected="));
      Serial.println(relay_connected ? F("yes") : F("no"));
      return true;
    }

    if(action == "set" && args.size() >= 6) {
      const String host = args.get(3);
      const long port_value = args.get(4).toInt();
      const String path = args.get(5);

      if(host.length() == 0 || port_value <= 0 || port_value > 65535) {
        Serial.println(F("ERR: invalid relay settings"));
        return true;
      }

      saveRelayConfig(host, (uint16_t)port_value, path, relay_ca);
      stopRelay();
      Serial.println(F("OK: endpoint saved; provision CA certificate via kor provision"));
      return true;
    }
  }

  if(sub == "provision") {
    startProvisioning();
    Serial.println(F("OK"));
    return true;
  }

  if(sub == "token" && args.size() >= 3) {
    const String token = args.get(2);

    if(token.length() < 64) {
      Serial.println(F("ERR: token must be at least 64 chars"));
      return true;
    }

    prefs.begin("korbridge", false);
    prefs.putString("token", token);
    prefs.end();

    auth_token = token;
    stopRelay();
    Serial.println(F("OK"));
    return true;
  }

  Serial.println(F("ERR: unknown kor command"));
  return true;
}

#endif
