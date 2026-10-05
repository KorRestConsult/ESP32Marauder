#include "KorBridge.h"

#ifdef MARAUDER_KOR_BRIDGE

#include <WiFi.h>
#include <Preferences.h>
#include <WebServer.h>
#include <WebSocketsClient.h>
#include <ArduinoJson.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/stream_buffer.h>

#include "configs.h"
#include "kor_expansion_protocol.h"

namespace {
constexpr uint32_t KOR_RPC_BAUD = 115200;
constexpr uint32_t KOR_FRAME_TIMEOUT_MS = 180;
constexpr uint32_t KOR_WIFI_RETRY_MS = 10000;
constexpr uint32_t KOR_RELAY_RETRY_MS = 5000;
constexpr uint32_t KOR_APP_HEARTBEAT_MS = 20000;
constexpr uint8_t KOR_WIFI_SLOTS = 8;
constexpr uint8_t KOR_NONCE_HISTORY = 8;

Preferences prefs;
WebServer provisioning_server(80);
WebSocketsClient relay_ws;

StreamBufferHandle_t to_flipper = nullptr;
StreamBufferHandle_t from_flipper = nullptr;
TaskHandle_t rpc_task_handle = nullptr;

bool bridge_active = false;
bool provisioning_active = false;
bool relay_started = false;
bool relay_connected = false;

uint32_t last_wifi_attempt = 0;
uint32_t last_relay_attempt = 0;
uint32_t last_app_heartbeat = 0;
uint32_t last_remote_seq = 0;
uint8_t wifi_failures = 0;

String device_id;
String provisioning_ssid;
String provisioning_password;

String relay_host;
String relay_path;
String relay_ca;
String relay_token;
uint16_t relay_port = 443;

String nonce_history[KOR_NONCE_HISTORY];
uint8_t nonce_cursor = 0;

String keyFor(const char* prefix, uint8_t index) {
  return String(prefix) + String(index);
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
  if(ssid.length() == 0) return false;

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

String makeDeviceId() {
  uint64_t mac = ESP.getEfuseMac();
  char buf[17];
  snprintf(buf, sizeof(buf), "%04X%08X", (uint16_t)(mac >> 32), (uint32_t)mac);
  return String(buf);
}

String ensureToken() {
  prefs.begin("korbridge", false);
  String token = prefs.getString("token", "");
  if(token.length() < 32) {
    uint64_t mac = ESP.getEfuseMac();
    char buf[64];
    snprintf(
      buf,
      sizeof(buf),
      "%08lX%08lX%08lX%08lX",
      (unsigned long)(mac >> 32),
      (unsigned long)mac,
      (unsigned long)esp_random(),
      (unsigned long)esp_random());
    token = String(buf);
    prefs.putString("token", token);
  }
  prefs.end();
  return token;
}

void loadReplayState() {
  prefs.begin("korbridge", true);
  last_remote_seq = prefs.getULong("last_seq", 0);
  prefs.end();
}

void saveReplayState(uint32_t seq) {
  last_remote_seq = seq;
  prefs.begin("korbridge", false);
  prefs.putULong("last_seq", seq);
  prefs.end();
}

void loadRelayConfig() {
  prefs.begin("korbridge", true);
  relay_host = prefs.getString("relay_host", "");
  relay_port = prefs.getUShort("relay_port", 443);
  relay_path = prefs.getString("relay_path", "/v1/device");
  relay_ca = prefs.getString("relay_ca", "");
  relay_token = prefs.getString("token", "");
  prefs.end();

  if(relay_path.length() == 0 || relay_path.charAt(0) != '/') {
    relay_path = "/v1/device";
  }
}

bool relayConfigReady() {
  return relay_host.length() > 0 &&
         relay_port > 0 &&
         relay_path.length() > 0 &&
         relay_ca.length() > 0 &&
         relay_token.length() >= 32;
}

bool nonceSeen(const String& nonce) {
  if(nonce.length() < 8 || nonce.length() > 96) return true;
  for(uint8_t i = 0; i < KOR_NONCE_HISTORY; ++i) {
    if(nonce_history[i] == nonce) return true;
  }
  return false;
}

void rememberNonce(const String& nonce) {
  nonce_history[nonce_cursor] = nonce;
  nonce_cursor = (nonce_cursor + 1) % KOR_NONCE_HISTORY;
}

String statusJson(const char* type = "status") {
  StaticJsonDocument<768> doc;
  doc["type"] = type;
  doc["protocol"] = "kor-bridge-v1";
  doc["device"] = device_id;
  doc["firmware"] = MARAUDER_VERSION;
  doc["hardware"] = HARDWARE_NAME;
  doc["uptime_ms"] = millis();
  doc["heap_free"] = ESP.getFreeHeap();
  doc["readonly"] = true;
  doc["bridge_mode"] = bridge_active;
  doc["relay_connected"] = relay_connected;
  doc["relay_configured"] = relayConfigReady();
  doc["wifi_profiles"] = wifiProfileCount();
  doc["rpc_transport"] = "staged";

  if(WiFi.status() == WL_CONNECTED) {
    doc["wifi_connected"] = true;
    doc["ssid"] = WiFi.SSID();
    doc["rssi"] = WiFi.RSSI();
    doc["ip"] = WiFi.localIP().toString();
  } else {
    doc["wifi_connected"] = false;
  }

  String out;
  serializeJson(doc, out);
  return out;
}

void relaySendLog(const char* level, const char* event, const String& detail = "") {
  if(!relay_connected) return;

  StaticJsonDocument<512> doc;
  doc["type"] = "log";
  doc["device"] = device_id;
  doc["level"] = level;
  doc["event"] = event;
  doc["uptime_ms"] = millis();
  if(detail.length()) doc["detail"] = detail;

  String out;
  serializeJson(doc, out);
  relay_ws.sendTXT(out);
}

void sendCommandResponse(uint32_t seq, const String& nonce, const char* status, const char* message) {
  if(!relay_connected) return;

  StaticJsonDocument<512> doc;
  doc["type"] = "result";
  doc["seq"] = seq;
  doc["nonce"] = nonce;
  doc["status"] = status;
  doc["message"] = message;

  String out;
  serializeJson(doc, out);
  relay_ws.sendTXT(out);
}

bool acceptEnvelope(uint32_t seq, const String& nonce) {
  if(seq == 0 || seq <= last_remote_seq) return false;
  if(nonceSeen(nonce)) return false;
  rememberNonce(nonce);
  saveReplayState(seq);
  return true;
}

void handleRelayText(uint8_t* payload, size_t length) {
  StaticJsonDocument<768> doc;
  DeserializationError err = deserializeJson(doc, payload, length);
  if(err) {
    relaySendLog("warn", "invalid_json");
    return;
  }

  const char* type = doc["type"] | "";
  if(strcmp(type, "cmd") != 0) {
    relaySendLog("warn", "invalid_message_type", type);
    return;
  }

  uint32_t seq = doc["seq"] | 0U;
  String nonce = String((const char*)(doc["nonce"] | ""));
  String cmd = String((const char*)(doc["cmd"] | ""));

  if(!acceptEnvelope(seq, nonce)) {
    relaySendLog("warn", "replay_rejected");
    sendCommandResponse(seq, nonce, "denied", "replay_or_invalid_envelope");
    return;
  }

  // Milestone 1 is deliberately read-only. No payload is forwarded to Flipper RPC yet.
  if(cmd == "status") {
    StaticJsonDocument<1024> out_doc;
    deserializeJson(out_doc, statusJson("result"));
    out_doc["seq"] = seq;
    out_doc["nonce"] = nonce;
    out_doc["status"] = "ok";
    String out;
    serializeJson(out_doc, out);
    relay_ws.sendTXT(out);
    return;
  }

  if(cmd == "ping") {
    sendCommandResponse(seq, nonce, "ok", "pong");
    return;
  }

  if(cmd == "capabilities") {
    StaticJsonDocument<768> out_doc;
    out_doc["type"] = "result";
    out_doc["seq"] = seq;
    out_doc["nonce"] = nonce;
    out_doc["status"] = "ok";
    JsonArray caps = out_doc.createNestedArray("capabilities");
    caps.add("status");
    caps.add("ping");
    caps.add("capabilities");
    out_doc["readonly"] = true;
    out_doc["rpc_transport"] = "staged";
    String out;
    serializeJson(out_doc, out);
    relay_ws.sendTXT(out);
    return;
  }

  relaySendLog("warn", "command_denied", cmd);
  sendCommandResponse(seq, nonce, "denied", "command_not_allowlisted");
}

void onRelayEvent(WStype_t type, uint8_t* payload, size_t length) {
  switch(type) {
    case WStype_CONNECTED:
      relay_connected = true;
      relay_ws.sendTXT(statusJson("hello"));
      relaySendLog("info", "relay_connected");
      break;

    case WStype_DISCONNECTED:
      relay_connected = false;
      break;

    case WStype_TEXT:
      handleRelayText(payload, length);
      break;

    case WStype_BIN:
      // Passive/read-only milestone: binary RPC frames are not accepted remotely yet.
      relaySendLog("warn", "binary_frame_denied");
      break;

    default:
      break;
  }
}

void stopRelay() {
  if(relay_started) relay_ws.disconnect();
  relay_started = false;
  relay_connected = false;
}

bool startRelay() {
  loadRelayConfig();
  if(!relayConfigReady()) return false;
  if(WiFi.status() != WL_CONNECTED) return false;

  stopRelay();

  String headers = "Authorization: Bearer " + relay_token +
                   "\r\nX-KOR-Device: " + device_id +
                   "\r\nX-KOR-Protocol: kor-bridge-v1";

  relay_ws.onEvent(onRelayEvent);
  relay_ws.setExtraHeaders(headers.c_str());
  relay_ws.setReconnectInterval(KOR_RELAY_RETRY_MS);
  relay_ws.enableHeartbeat(15000, 3000, 2);

  // Fail closed: CA must be provisioned. No setInsecure() fallback exists here.
  relay_ws.beginSslWithCA(
    relay_host.c_str(),
    relay_port,
    relay_path.c_str(),
    relay_ca.c_str(),
    "kor-bridge-v1");

  relay_started = true;
  last_relay_attempt = millis();
  return true;
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

void startProvisioning() {
  if(provisioning_active) return;

  String token = ensureToken();
  provisioning_ssid = "KOR-Setup-" + device_id.substring(device_id.length() - 6);
  provisioning_password = token.substring(0, 12);

  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(provisioning_ssid.c_str(), provisioning_password.c_str());

  provisioning_server.on("/", HTTP_GET, []() {
    loadRelayConfig();

    String page;
    page.reserve(5000);
    page += F("<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>");
    page += F("<title>KOR Bridge</title></head><body><h2>KOR Bridge provisioning</h2>");
    page += F("<p>Device: ");
    page += htmlEscape(device_id);
    page += F("</p><form method='POST' action='/save'>");
    page += F("<h3>Wi-Fi profile</h3><input name='ssid' placeholder='SSID'><br>");
    page += F("<input name='password' type='password' placeholder='Password (empty for open network)'><br>");
    page += F("<h3>Relay</h3><input name='host' placeholder='relay.example.com' value='");
    page += htmlEscape(relay_host);
    page += F("'><br><input name='port' type='number' value='");
    page += String(relay_port);
    page += F("'><br><input name='path' value='");
    page += htmlEscape(relay_path);
    page += F("'><br><textarea name='ca' rows='12' cols='48' placeholder='PEM CA certificate'>");
    page += htmlEscape(relay_ca);
    page += F("</textarea><br><button type='submit'>Save and reboot</button></form>");
    page += F("<form method='POST' action='/disable'><button type='submit'>Disable KOR Bridge and reboot to Marauder</button></form>");
    page += F("</body></html>");
    provisioning_server.send(200, "text/html; charset=utf-8", page);
  });

  provisioning_server.on("/status", HTTP_GET, []() {
    provisioning_server.send(200, "application/json", statusJson());
  });

  provisioning_server.on("/save", HTTP_POST, []() {
    if(provisioning_server.hasArg("ssid")) {
      String ssid = provisioning_server.arg("ssid");
      String password = provisioning_server.arg("password");
      if(ssid.length()) saveWifiProfile(ssid, password);
    }

    prefs.begin("korbridge", false);
    if(provisioning_server.hasArg("host")) prefs.putString("relay_host", provisioning_server.arg("host"));
    if(provisioning_server.hasArg("port")) {
      uint16_t port = (uint16_t)provisioning_server.arg("port").toInt();
      if(port > 0) prefs.putUShort("relay_port", port);
    }
    if(provisioning_server.hasArg("path")) prefs.putString("relay_path", provisioning_server.arg("path"));
    if(provisioning_server.hasArg("ca")) prefs.putString("relay_ca", provisioning_server.arg("ca"));
    prefs.end();

    provisioning_server.send(200, "text/plain", "Saved. Rebooting.");
    delay(250);
    ESP.restart();
  });

  provisioning_server.on("/disable", HTTP_POST, []() {
    prefs.begin("korbridge", false);
    prefs.putBool("enabled", false);
    prefs.end();
    provisioning_server.send(200, "text/plain", "KOR Bridge disabled. Rebooting to Marauder.");
    delay(250);
    ESP.restart();
  });

  provisioning_server.begin();
  provisioning_active = true;

  Serial.print(F("KOR provisioning AP: "));
  Serial.println(provisioning_ssid);
  Serial.print(F("KOR provisioning password: "));
  Serial.println(provisioning_password);
  Serial.println(F("KOR provisioning URL: http://192.168.4.1/"));
}

void stopProvisioning() {
  if(!provisioning_active) return;
  provisioning_server.stop();
  WiFi.softAPdisconnect(true);
  provisioning_active = false;
}

bool connectSavedWifi() {
  WiFi.mode(provisioning_active ? WIFI_AP_STA : WIFI_STA);
  WiFi.setAutoReconnect(true);

  for(uint8_t i = 0; i < KOR_WIFI_SLOTS; ++i) {
    String ssid, password;
    if(!loadWifiProfile(i, ssid, password)) continue;

    WiFi.disconnect(false, false);
    delay(50);

    if(password.length() > 0) WiFi.begin(ssid.c_str(), password.c_str());
    else WiFi.begin(ssid.c_str());

    const uint32_t start = millis();
    while(WiFi.status() != WL_CONNECTED && millis() - start < 7000) {
      if(provisioning_active) provisioning_server.handleClient();
      delay(100);
    }

    if(WiFi.status() == WL_CONNECTED) {
      wifi_failures = 0;
      relaySendLog("info", "wifi_connected", ssid);
      return true;
    }
  }

  ++wifi_failures;
  return false;
}

size_t serialReceive(uint8_t* data, size_t len, void*) {
  size_t got = 0;
  const uint32_t start = millis();
  while(got < len && (millis() - start) < KOR_FRAME_TIMEOUT_MS) {
    while(Serial.available() && got < len) {
      data[got++] = (uint8_t)Serial.read();
    }
    if(got < len) delay(1);
  }
  return got;
}

size_t serialSend(const uint8_t* data, size_t len, void*) {
  size_t sent = Serial.write(data, len);
  Serial.flush();
  return sent;
}

bool sendFrame(const ExpansionFrame& frame) {
  return expansion_protocol_encode(&frame, serialSend, nullptr) == ExpansionProtocolStatusOk;
}

bool receiveFrame(ExpansionFrame& frame) {
  memset(&frame, 0, sizeof(frame));
  return expansion_protocol_decode(&frame, serialReceive, nullptr) == ExpansionProtocolStatusOk;
}

bool isOk(const ExpansionFrame& frame) {
  return frame.header.type == ExpansionFrameTypeStatus &&
         frame.content.status.error == ExpansionFrameErrorNone;
}

bool sendHeartbeat() {
  ExpansionFrame f{};
  f.header.type = ExpansionFrameTypeHeartbeat;
  return sendFrame(f);
}

bool sendStatus() {
  ExpansionFrame f{};
  f.header.type = ExpansionFrameTypeStatus;
  f.content.status.error = ExpansionFrameErrorNone;
  return sendFrame(f);
}

bool sendBaud(uint32_t baud) {
  ExpansionFrame f{};
  f.header.type = ExpansionFrameTypeBaudRate;
  f.content.baud_rate.baud = baud;
  return sendFrame(f);
}

bool sendControl(ExpansionFrameControlCommand cmd) {
  ExpansionFrame f{};
  f.header.type = ExpansionFrameTypeControl;
  f.content.control.command = cmd;
  return sendFrame(f);
}

bool sendData(const uint8_t* data, size_t len) {
  if(len > EXPANSION_PROTOCOL_MAX_DATA_SIZE) return false;
  ExpansionFrame f{};
  f.header.type = ExpansionFrameTypeData;
  f.content.data.size = len;
  memcpy(f.content.data.bytes, data, len);
  return sendFrame(f);
}

bool startRpcSession() {
  Serial.updateBaudRate(EXPANSION_PROTOCOL_DEFAULT_BAUD_RATE);
  while(Serial.available()) Serial.read();

  Serial.write((uint8_t)0xF0);
  Serial.flush();

  ExpansionFrame rx{};
  if(!receiveFrame(rx) || rx.header.type != ExpansionFrameTypeHeartbeat) return false;

  if(!sendBaud(KOR_RPC_BAUD)) return false;
  if(!receiveFrame(rx) || !isOk(rx)) return false;

  Serial.updateBaudRate(KOR_RPC_BAUD);
  delay(EXPANSION_PROTOCOL_BAUD_CHANGE_DT_MS);

  if(!sendControl(ExpansionFrameControlCommandStartRpc)) return false;
  if(!receiveFrame(rx) || !isOk(rx)) return false;

  return true;
}

void rpcTask(void*) {
  Serial.end();
  delay(20);
  Serial.begin(EXPANSION_PROTOCOL_DEFAULT_BAUD_RATE);
  delay(250);

  uint8_t txbuf[EXPANSION_PROTOCOL_MAX_DATA_SIZE];

  while(true) {
    if(!startRpcSession()) {
      delay(150);
      continue;
    }

    while(true) {
      size_t n = xStreamBufferReceive(to_flipper, txbuf, sizeof(txbuf), 0);
      if(n > 0) {
        if(!sendData(txbuf, n)) break;

        ExpansionFrame ack{};
        if(!receiveFrame(ack)) break;

        if(ack.header.type == ExpansionFrameTypeData) {
          if(!sendStatus()) break;
          xStreamBufferSend(from_flipper, ack.content.data.bytes, ack.content.data.size, 0);
          if(!receiveFrame(ack)) break;
        }

        if(!isOk(ack)) break;
        continue;
      }

      ExpansionFrame rx{};
      if(receiveFrame(rx)) {
        if(rx.header.type == ExpansionFrameTypeData) {
          if(!sendStatus()) break;
          xStreamBufferSend(from_flipper, rx.content.data.bytes, rx.content.data.size, 0);
        } else if(rx.header.type == ExpansionFrameTypeHeartbeat) {
          if(!sendHeartbeat()) break;
        } else if(rx.header.type == ExpansionFrameTypeStatus) {
          if(rx.content.status.error != ExpansionFrameErrorNone) break;
        } else {
          break;
        }
      } else {
        if(!sendHeartbeat()) break;
        if(!receiveFrame(rx)) break;
        if(rx.header.type == ExpansionFrameTypeData) {
          if(!sendStatus()) break;
          xStreamBufferSend(from_flipper, rx.content.data.bytes, rx.content.data.size, 0);
        } else if(rx.header.type != ExpansionFrameTypeHeartbeat) {
          break;
        }
      }
    }

    Serial.updateBaudRate(EXPANSION_PROTOCOL_DEFAULT_BAUD_RATE);
    delay(100);
  }
}

void printStatus() {
  loadRelayConfig();

  Serial.println(F("@KOR:{"));
  Serial.print(F("  firmware: "));
  Serial.println(MARAUDER_VERSION);
  Serial.print(F("  hardware: "));
  Serial.println(HARDWARE_NAME);
  Serial.print(F("  mode: "));
  Serial.println(KorBridge::enabled() ? F("bridge") : F("marauder"));
  Serial.print(F("  device: "));
  Serial.println(device_id.length() ? device_id : makeDeviceId());
  Serial.print(F("  uptime_ms: "));
  Serial.println(millis());
  Serial.print(F("  heap_free: "));
  Serial.println(ESP.getFreeHeap());
  Serial.print(F("  wifi_profiles: "));
  Serial.println(wifiProfileCount());
  Serial.print(F("  wifi_status: "));
  Serial.println(WiFi.status() == WL_CONNECTED ? F("connected") : F("disconnected"));
  if(WiFi.status() == WL_CONNECTED) {
    Serial.print(F("  ssid: "));
    Serial.println(WiFi.SSID());
    Serial.print(F("  rssi: "));
    Serial.println(WiFi.RSSI());
    Serial.print(F("  ip: "));
    Serial.println(WiFi.localIP());
  }
  Serial.print(F("  relay_configured: "));
  Serial.println(relayConfigReady() ? F("yes") : F("no"));
  Serial.print(F("  relay_connected: "));
  Serial.println(relay_connected ? F("yes") : F("no"));
  Serial.print(F("  provisioning: "));
  Serial.println(provisioning_active ? F("active") : F("off"));
  Serial.println(F("  readonly: yes"));
  Serial.println(F("  rpc_transport: staged"));
  Serial.println(F("}"));
}
}

bool KorBridge::enabled() {
  prefs.begin("korbridge", true);
  bool value = prefs.getBool("enabled", false);
  prefs.end();
  return value;
}

bool KorBridge::active() {
  return bridge_active;
}

void KorBridge::begin() {
  bridge_active = true;
  device_id = makeDeviceId();
  relay_token = ensureToken();
  loadReplayState();
  loadRelayConfig();

  // Keep the Expansion RPC implementation compiled and ready, but do not start it
  // in milestone 1. Remote commands remain passive/read-only until explicitly promoted.
#ifdef MARAUDER_KOR_RPC_EXPERIMENTAL
  to_flipper = xStreamBufferCreate(4096, 1);
  from_flipper = xStreamBufferCreate(4096, 1);
  xTaskCreate(rpcTask, "kor_rpc", 6144, nullptr, 2, &rpc_task_handle);
#endif

  if(!connectSavedWifi()) {
    startProvisioning();
  } else if(relayConfigReady()) {
    startRelay();
  } else {
    startProvisioning();
  }
}

void KorBridge::loop() {
  if(provisioning_active) {
    provisioning_server.handleClient();
  }

  if(WiFi.status() != WL_CONNECTED) {
    if(relay_started) stopRelay();

    if(millis() - last_wifi_attempt >= KOR_WIFI_RETRY_MS) {
      last_wifi_attempt = millis();
      if(!connectSavedWifi() && wifi_failures >= 2) {
        startProvisioning();
      }
    }

    delay(5);
    return;
  }

  if(!relay_started && relayConfigReady() && millis() - last_relay_attempt >= KOR_RELAY_RETRY_MS) {
    last_relay_attempt = millis();
    startRelay();
  }

  if(relay_started) relay_ws.loop();

  if(relay_connected && millis() - last_app_heartbeat >= KOR_APP_HEARTBEAT_MS) {
    last_app_heartbeat = millis();
    relay_ws.sendTXT(statusJson("heartbeat"));
  }

  delay(1);
}

bool KorBridge::handleCli(LinkedList<String>& args) {
  if(args.size() == 0 || args.get(0) != "kor") return false;

  if(args.size() == 1 || args.get(1) == "help") {
    Serial.println(F("kor status"));
    Serial.println(F("kor bridge on|off"));
    Serial.println(F("kor wifi list"));
    Serial.println(F("kor wifi add <ssid> [password]"));
    Serial.println(F("kor wifi remove <index>"));
    Serial.println(F("kor relay show"));
    Serial.println(F("kor relay set <host> <port> <path>"));
    Serial.println(F("kor provisioning start"));
    Serial.println(F("kor token <value>"));
    return true;
  }

  const String sub = args.get(1);

  if(sub == "status") {
    printStatus();
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
          Serial.print(ssid);
          Serial.println(password.length() ? F(" [secured]") : F(" [open]"));
        }
      }
      return true;
    }

    if(action == "add" && args.size() >= 4) {
      String ssid = args.get(3);
      String password = args.size() >= 5 ? args.get(4) : "";
      Serial.println(saveWifiProfile(ssid, password) ? F("OK") : F("ERR"));
      return true;
    }

    if(action == "remove" && args.size() >= 4) {
      int idx = args.get(3).toInt();
      Serial.println(removeWifiProfile((uint8_t)idx) ? F("OK") : F("ERR"));
      return true;
    }
  }

  if(sub == "relay" && args.size() >= 3) {
    const String action = args.get(2);

    if(action == "show") {
      loadRelayConfig();
      Serial.print(F("host: "));
      Serial.println(relay_host);
      Serial.print(F("port: "));
      Serial.println(relay_port);
      Serial.print(F("path: "));
      Serial.println(relay_path);
      Serial.print(F("ca_set: "));
      Serial.println(relay_ca.length() ? F("yes") : F("no"));
      Serial.print(F("token_set: "));
      Serial.println(relay_token.length() >= 32 ? F("yes") : F("no"));
      return true;
    }

    if(action == "set" && args.size() >= 6) {
      const String host = args.get(3);
      const uint16_t port = (uint16_t)args.get(4).toInt();
      String path = args.get(5);
      if(host.length() == 0 || port == 0) {
        Serial.println(F("ERR"));
        return true;
      }
      if(path.length() == 0 || path.charAt(0) != '/') path = "/" + path;

      prefs.begin("korbridge", false);
      prefs.putString("relay_host", host);
      prefs.putUShort("relay_port", port);
      prefs.putString("relay_path", path);
      prefs.end();
      Serial.println(F("OK: relay endpoint saved; CA still required via provisioning page"));
      return true;
    }
  }

  if(sub == "provisioning" && args.size() >= 3 && args.get(2) == "start") {
    device_id = makeDeviceId();
    startProvisioning();
    return true;
  }

  if(sub == "token" && args.size() >= 3) {
    String token = args.get(2);
    if(token.length() < 32) {
      Serial.println(F("ERR: token must be at least 32 chars"));
      return true;
    }
    prefs.begin("korbridge", false);
    prefs.putString("token", token);
    prefs.end();
    Serial.println(F("OK"));
    return true;
  }

  Serial.println(F("ERR: unknown kor command"));
  return true;
}

#endif
