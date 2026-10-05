#include "KorBridge.h"

#ifdef MARAUDER_KOR_BRIDGE

#include "configs.h"

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
constexpr uint32_t KOR_WIFI_RETRY_MS = 15000;
constexpr uint32_t KOR_APP_HEARTBEAT_MS = 15000;
constexpr uint16_t KOR_DEFAULT_RELAY_PORT = 443;

Preferences prefs;
WebServer provision_server(80);
WebSocketsClient web_socket;

bool bridge_active = false;
bool provisioning = false;
bool provision_routes_ready = false;
bool provision_saved = false;
bool relay_started = false;
bool relay_connected = false;
bool relay_authenticated = false;
bool marauder_busy = false;

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
String relay_fingerprint;
uint16_t relay_port = KOR_DEFAULT_RELAY_PORT;
String local_cli_line;

String keyFor(const char* prefix, uint8_t index) {
  return String(prefix) + String(index);
}

String u64ToString(uint64_t value) {
  char buf[24];
  snprintf(buf, sizeof(buf), "%llu", (unsigned long long)value);
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
  if(token.length() < 48) {
    token = randomHex(32);
    prefs.putString("token", token);
  }
  prefs.end();
  return token;
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

  mbedtls_md_hmac_starts(
    &ctx,
    reinterpret_cast<const unsigned char*>(key.c_str()),
    key.length());
  mbedtls_md_hmac_update(
    &ctx,
    reinterpret_cast<const unsigned char*>(message.c_str()),
    message.length());
  mbedtls_md_hmac_finish(&ctx, digest);
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
  for(size_t i = 0; i < a.length(); ++i) diff |= (uint8_t)(a[i] ^ b[i]);
  return diff == 0;
}

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

bool openNetworksAllowed() {
  prefs.begin("korbridge", true);
  const bool allowed = prefs.getBool("allow_open", true);
  prefs.end();
  return allowed;
}

void setOpenNetworksAllowed(bool allowed) {
  prefs.begin("korbridge", false);
  prefs.putBool("allow_open", allowed);
  prefs.end();
}

void loadRelayConfig() {
  prefs.begin("korbridge", true);
  relay_host = prefs.getString("relay_host", "");
  relay_path = prefs.getString("relay_path", "/device");
  relay_fingerprint = prefs.getString("relay_fp", "");
  uint32_t stored_port = prefs.getUInt("relay_port", KOR_DEFAULT_RELAY_PORT);
  prefs.end();

  if(stored_port == 0 || stored_port > 65535) stored_port = KOR_DEFAULT_RELAY_PORT;
  relay_port = (uint16_t)stored_port;
  if(relay_path.length() == 0) relay_path = "/device";
  if(relay_path[0] != '/') relay_path = "/" + relay_path;
}

void saveRelayConfig(
  const String& host,
  uint16_t port,
  const String& path,
  const String& fingerprint) {
  prefs.begin("korbridge", false);
  prefs.putString("relay_host", host);
  prefs.putUInt("relay_port", port);
  prefs.putString("relay_path", path.length() ? path : "/device");
  prefs.putString("relay_fp", fingerprint);
  prefs.end();
  loadRelayConfig();
}

bool relayConfigReady() {
  return relay_host.length() > 0 &&
         relay_path.length() > 0 &&
         relay_fingerprint.length() >= 40 &&
         auth_token.length() >= 48;
}

String buildStatusJson() {
  DynamicJsonDocument doc(768);
  doc["firmware"] = MARAUDER_VERSION;
  doc["bridge_mode"] = bridge_active ? "passive-read-only" : "inactive";
  doc["device"] = device_id;
  doc["uptime_ms"] = millis();
  doc["heap_free"] = ESP.getFreeHeap();
  doc["wifi_profiles"] = wifiProfileCount();
  doc["allow_open_wifi"] = openNetworksAllowed();
  doc["wifi_connected"] = WiFi.status() == WL_CONNECTED;
  doc["relay_configured"] = relayConfigReady();
  doc["relay_connected"] = relay_connected;
  doc["relay_authenticated"] = relay_authenticated;
  doc["provisioning"] = provisioning;
  doc["rpc"] = "disabled-passive-milestone";
  doc["marauder_busy"] = marauder_busy;

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
  const String canonical =
    device_id + "|" + boot_nonce + "|" + u64ToString(seq) + "|" +
    String(type) + "|" + name + "|" + payload;

  DynamicJsonDocument doc(1792);
  doc["v"] = 1;
  doc["type"] = type;
  doc["device"] = device_id;
  doc["session"] = boot_nonce;
  doc["seq"] = seq;
  doc["name"] = name;
  doc["payload"] = payload;
  doc["mac"] = hmacHex(auth_token, canonical);

  String out;
  serializeJson(doc, out);
  web_socket.sendTXT(out);
}

void remoteLog(const String& level, const String& message) {
  if(!relay_authenticated) return;

  DynamicJsonDocument doc(512);
  doc["level"] = level;
  doc["message"] = message;

  String payload;
  serializeJson(doc, payload);
  sendEnvelope("event", "log", payload);
}

bool verifyCommonEnvelope(JsonDocument& doc, const String& expected_type, String& canonical) {
  if((doc["v"] | 0) != 1) return false;
  if(String((const char*)(doc["type"] | "")) != expected_type) return false;
  if(String((const char*)(doc["device"] | "")) != device_id) return false;
  if(String((const char*)(doc["session"] | "")) != boot_nonce) return false;

  const uint32_t seq = doc["seq"].as<uint32_t>();
  if(seq == 0 || seq <= last_rx_seq) return false;

  const String mac = String((const char*)(doc["mac"] | ""));
  if(mac.length() != 64) return false;

  canonical = device_id + "|" + boot_nonce + "|" + u64ToString(seq) + "|" + expected_type;
  return true;
}

void handleRelayText(uint8_t* payload, size_t length) {
  DynamicJsonDocument doc(1536);
  const DeserializationError err = deserializeJson(doc, payload, length);
  if(err) return;

  const String type = String((const char*)(doc["type"] | ""));

  if(type == "auth") {
    String canonical;
    if(!verifyCommonEnvelope(doc, "auth", canonical)) return;

    const String expected = hmacHex(auth_token, canonical);
    const String provided = String((const char*)(doc["mac"] | ""));
    if(!secureEqual(expected, provided)) return;

    last_rx_seq = doc["seq"].as<uint32_t>();
    relay_authenticated = true;
    sendEnvelope("event", "status", buildStatusJson());
    remoteLog("info", "relay authenticated");
    return;
  }

  if(type != "cmd" || !relay_authenticated) return;

  String canonical;
  if(!verifyCommonEnvelope(doc, "cmd", canonical)) return;

  const String cmd = String((const char*)(doc["cmd"] | ""));
  canonical += "|" + cmd;

  const String expected = hmacHex(auth_token, canonical);
  const String provided = String((const char*)(doc["mac"] | ""));
  if(!secureEqual(expected, provided)) return;

  last_rx_seq = doc["seq"].as<uint32_t>();

  if(cmd == "status") {
    sendEnvelope("response", "status", buildStatusJson());
  } else if(cmd == "ping") {
    sendEnvelope("response", "pong", "{\"ok\":true}");
  } else {
    sendEnvelope("response", "denied", "{\"error\":\"read_only_allowlist\"}");
    remoteLog("warn", "denied remote command: " + cmd);
  }
}

void webSocketEvent(WStype_t type, uint8_t* payload, size_t length) {
  switch(type) {
    case WStype_CONNECTED:
      relay_connected = true;
      relay_authenticated = false;
      last_rx_seq = 0;
      sendEnvelope("hello", "device", buildStatusJson());
      break;

    case WStype_DISCONNECTED:
      relay_connected = false;
      relay_authenticated = false;
      break;

    case WStype_TEXT:
      handleRelayText(payload, length);
      break;

    default:
      break;
  }
}

void stopRelay() {
  if(relay_started) web_socket.disconnect();
  relay_started = false;
  relay_connected = false;
  relay_authenticated = false;
  last_rx_seq = 0;
}

void startRelay() {
  if(relay_started || WiFi.status() != WL_CONNECTED || !relayConfigReady()) return;

  web_socket.onEvent(webSocketEvent);
  web_socket.setReconnectInterval(5000);
  web_socket.enableHeartbeat(15000, 3000, 2);
  web_socket.beginSSL(
    relay_host.c_str(),
    relay_port,
    relay_path.c_str(),
    relay_fingerprint.c_str(),
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
  WiFi.mode(provisioning ? WIFI_AP_STA : WIFI_STA);
  WiFi.setAutoReconnect(true);

  for(uint8_t i = 0; i < KOR_WIFI_SLOTS; ++i) {
    String ssid, password;
    if(!loadWifiProfile(i, ssid, password)) continue;

    WiFi.disconnect(false, false);
    delay(50);

    if(password.length() > 0) WiFi.begin(ssid.c_str(), password.c_str());
    else WiFi.begin(ssid.c_str());

    if(waitForWifi(7000)) return true;
  }

  return false;
}

bool connectBestOpenWifi() {
  if(!openNetworksAllowed()) return false;

  WiFi.mode(provisioning ? WIFI_AP_STA : WIFI_STA);
  const int count = WiFi.scanNetworks(false, true);
  if(count <= 0) return false;

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
  return waitForWifi(7000);
}

void prepareProvisionRoutes() {
  if(provision_routes_ready) return;
  provision_routes_ready = true;

  provision_server.on("/", HTTP_GET, []() {
    String page =
      "<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
      "<title>KOR Bridge</title></head><body><h2>KOR Bridge provisioning</h2>"
      "<p>Device: " + device_id + "</p>"
      "<form method='POST' action='/save'>"
      "<label>Wi-Fi SSID</label><br><input name='ssid' maxlength='32'><br>"
      "<label>Wi-Fi password (blank=open)</label><br><input name='password' type='password' maxlength='63'><br>"
      "<label>Relay host</label><br><input name='relay_host'><br>"
      "<label>Relay port</label><br><input name='relay_port' value='443'><br>"
      "<label>Relay path</label><br><input name='relay_path' value='/device'><br>"
      "<label>TLS SHA1 fingerprint</label><br><input name='relay_fp'><br><br>"
      "<button type='submit'>Save</button></form>"
      "<p>After saving, reconnect your phone to normal Wi-Fi.</p></body></html>";

    provision_server.send(200, "text/html", page);
  });

  provision_server.on("/status", HTTP_GET, []() {
    provision_server.send(200, "application/json", buildStatusJson());
  });

  provision_server.on("/save", HTTP_POST, []() {
    const String ssid = provision_server.arg("ssid");
    const String password = provision_server.arg("password");
    const String host = provision_server.arg("relay_host");
    const String path = provision_server.arg("relay_path");
    const String fingerprint = provision_server.arg("relay_fp");
    long port_value = provision_server.arg("relay_port").toInt();

    if(port_value <= 0 || port_value > 65535) port_value = KOR_DEFAULT_RELAY_PORT;

    bool ok = true;
    if(ssid.length()) ok = saveWifiProfile(ssid, password);
    if(host.length()) {
      if(fingerprint.length() < 40) ok = false;
      else saveRelayConfig(host, (uint16_t)port_value, path, fingerprint);
    }

    provision_saved = ok;
    provision_server.send(
      ok ? 200 : 400,
      "text/plain",
      ok ? "Saved. KOR Bridge will reconnect." : "Invalid settings.");
  });
}

void startProvisioning() {
  if(provisioning) return;

  provisioning = true;
  if(ap_password.length() < 12) ap_password = randomHex(8);

  WiFi.mode(WIFI_AP_STA);
  const String ssid = "KOR-" + device_id.substring(device_id.length() > 6 ? device_id.length() - 6 : 0);
  WiFi.softAP(ssid.c_str(), ap_password.c_str());

  prepareProvisionRoutes();
  provision_server.begin();

  Serial.println(F("@KOR provisioning active"));
  Serial.print(F("@KOR AP: "));
  Serial.println(ssid);
  Serial.print(F("@KOR AP password: "));
  Serial.println(ap_password);
  Serial.println(F("@KOR URL: http://192.168.4.1/"));
}

void stopProvisioning() {
  if(!provisioning) return;
  provision_server.stop();
  WiFi.softAPdisconnect(true);
  provisioning = false;
  provision_saved = false;
  WiFi.mode(WIFI_STA);
}

LinkedList<String> parseLocalArgs(const String& input) {
  LinkedList<String> out;
  String token;
  bool quoted = false;
  char quote_char = 0;

  for(size_t i = 0; i < input.length(); ++i) {
    const char c = input.charAt(i);

    if((c == '"' || c == '\'') && (!quoted || c == quote_char)) {
      if(!quoted) {
        quoted = true;
        quote_char = c;
      } else {
        quoted = false;
        quote_char = 0;
      }
      continue;
    }

    if(c == ' ' && !quoted) {
      if(token.length()) {
        out.add(token);
        token = "";
      }
    } else {
      token += c;
    }
  }

  if(token.length()) out.add(token);
  return out;
}

void pumpLocalCli() {
  while(Serial.available()) {
    const char c = (char)Serial.read();

    if(c == '\n') {
      local_cli_line.trim();
      if(local_cli_line.length()) {
        LinkedList<String> args = parseLocalArgs(local_cli_line);
        if(!KorBridge::handleCli(args)) Serial.println(F("ERR: bridge mode accepts only kor commands"));
      }
      local_cli_line = "";
      continue;
    }

    if(c != '\r') {
      local_cli_line += c;
      if(local_cli_line.length() > 512) local_cli_line = "";
    }
  }
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
  bridge_active = true;
  device_id = makeDeviceId();
  boot_nonce = randomHex(16);
  auth_token = ensureToken();
  loadRelayConfig();

  WiFi.persistent(false);
  WiFi.setAutoReconnect(true);

  if(!connectSavedWifi()) connectBestOpenWifi();

  if(WiFi.status() == WL_CONNECTED && relayConfigReady()) startRelay();
  else startProvisioning();

  Serial.println(F("@KOR bridge mode: PASSIVE/READ-ONLY"));
}

void KorBridge::loop(bool marauderBusy) {
  marauder_busy = marauderBusy;
  pumpLocalCli();

  if(provisioning) {
    provision_server.handleClient();

    if(provision_saved) {
      delay(250);
      stopProvisioning();
      stopRelay();
      WiFi.disconnect(false, false);
      last_wifi_attempt = 0;
    }
  }

  if(WiFi.status() != WL_CONNECTED) {
    if(relay_started) stopRelay();

    if(millis() - last_wifi_attempt >= KOR_WIFI_RETRY_MS) {
      last_wifi_attempt = millis();

      if(!connectSavedWifi() && !connectBestOpenWifi()) {
        startProvisioning();
      }
    }

    delay(5);
    return;
  }

  if(relayConfigReady()) {
    if(provisioning) stopProvisioning();
    startRelay();
    web_socket.loop();

    if(relay_authenticated && millis() - last_heartbeat >= KOR_APP_HEARTBEAT_MS) {
      last_heartbeat = millis();
      sendEnvelope("event", "heartbeat", buildStatusJson());
    }
  } else {
    startProvisioning();
  }

  delay(1);
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
    Serial.println(F("kor wifi open on|off"));
    Serial.println(F("kor relay show"));
    Serial.println(F("kor relay set <host> <port> <path> <sha1-fingerprint>"));
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

    if(on) ensureToken();

    prefs.begin("korbridge", false);
    prefs.putBool("enabled", on);
    prefs.end();

    Serial.println(on ? F("KOR Bridge enabled; rebooting") : F("KOR Bridge disabled; rebooting"));
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
          Serial.println(ssid);
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
      Serial.println(removeWifiProfile((uint8_t)idx) ? F("OK") : F("ERR"));
      return true;
    }

    if(action == "open" && args.size() >= 4) {
      if(args.get(3) == "on") setOpenNetworksAllowed(true);
      else if(args.get(3) == "off") setOpenNetworksAllowed(false);
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
      Serial.print(F("fingerprint="));
      Serial.println(relay_fingerprint.length() ? F("set") : F("not-set"));
      return true;
    }

    if(action == "set" && args.size() >= 7) {
      const String host = args.get(3);
      long port_value = args.get(4).toInt();
      const String path = args.get(5);
      const String fingerprint = args.get(6);

      if(host.length() == 0 || port_value <= 0 || port_value > 65535 || fingerprint.length() < 40) {
        Serial.println(F("ERR: invalid relay settings"));
        return true;
      }

      saveRelayConfig(host, (uint16_t)port_value, path, fingerprint);
      stopRelay();
      Serial.println(F("OK"));
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

    if(token.length() < 48) {
      Serial.println(F("ERR: token must be at least 48 chars"));
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
