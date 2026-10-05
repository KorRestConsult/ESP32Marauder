#include "KorBridge.h"

#ifdef MARAUDER_KOR_BRIDGE

#include "configs.h"

#include <ArduinoJson.h>
#include <Preferences.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <time.h>

namespace {
constexpr uint8_t KOR_WIFI_SLOTS = 8;
constexpr uint16_t KOR_PROVISION_PORT = 8080;
constexpr uint32_t KOR_WIFI_ATTEMPT_MS = 7000;
constexpr uint32_t KOR_WIFI_RETRY_CYCLE_MS = 30000;
constexpr uint32_t KOR_HEARTBEAT_MS = 20000;
constexpr uint32_t KOR_RELAY_BACKOFF_MIN_MS = 2000;
constexpr uint32_t KOR_RELAY_BACKOFF_MAX_MS = 60000;
constexpr size_t KOR_MAX_RELAY_LINE = 2048;
constexpr uint8_t KOR_LOG_SLOTS = 12;

Preferences prefs;
WiFiServer provisionServer(KOR_PROVISION_PORT);
WiFiClientSecure relayClient;

bool runtimeEnabled = false;
bool pausedForMarauder = false;
bool provisioning = false;
bool wifiAttemptActive = false;
bool openNetworkTried = false;
bool ntpStarted = false;

uint8_t wifiSlot = 0;
uint32_t wifiAttemptStarted = 0;
uint32_t nextWifiCycleAt = 0;
uint32_t nextRelayAttemptAt = 0;
uint32_t relayBackoffMs = KOR_RELAY_BACKOFF_MIN_MS;
uint32_t lastHeartbeatAt = 0;
uint32_t lastAcceptedSeq = 0;

String attemptingSsid;
String deviceId;
String apSsid;
String apPassword;
String bridgeState = "disabled";
String relayRx;

String relayHost;
uint16_t relayPort = 443;
String relayToken;
String relayCa;

String logs[KOR_LOG_SLOTS];
uint8_t logHead = 0;
uint8_t logCount = 0;

String keyFor(const char* prefix, uint8_t index) {
  return String(prefix) + String(index);
}

void addLog(const String& message) {
  logs[logHead] = String(millis()) + " " + message;
  logHead = (logHead + 1) % KOR_LOG_SLOTS;
  if(logCount < KOR_LOG_SLOTS) ++logCount;
}

String makeDeviceId() {
  const uint64_t mac = ESP.getEfuseMac();
  char buf[17];
  snprintf(buf, sizeof(buf), "%04X%08X", (uint16_t)(mac >> 32), (uint32_t)mac);
  return String(buf);
}

void loadRelayConfig() {
  prefs.begin("korbridge", true);
  relayHost = prefs.getString("relay_host", "");
  relayPort = prefs.getUShort("relay_port", 443);
  relayToken = prefs.getString("relay_token", "");
  relayCa = prefs.getString("relay_ca", "");
  lastAcceptedSeq = prefs.getUInt("last_seq", 0);
  prefs.end();
}

bool relayConfigured() {
  return relayHost.length() > 0 &&
         relayPort > 0 &&
         relayToken.length() >= 24 &&
         relayCa.indexOf("BEGIN CERTIFICATE") >= 0;
}

bool allowOpenNetworks() {
  prefs.begin("korbridge", true);
  const bool value = prefs.getBool("allow_open", false);
  prefs.end();
  return value;
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

  int target = -1;
  for(uint8_t i = 0; i < KOR_WIFI_SLOTS; ++i) {
    String saved, ignored;
    if(loadWifiProfile(i, saved, ignored)) {
      if(saved == ssid) {
        target = i;
        break;
      }
    } else if(target < 0) {
      target = i;
    }
  }

  if(target < 0) return false;

  prefs.begin("korbridge", false);
  prefs.putString(keyFor("s", target).c_str(), ssid);
  prefs.putString(keyFor("p", target).c_str(), password);
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

void ensureProvisioningIdentity() {
  if(deviceId.length() == 0) deviceId = makeDeviceId();

  prefs.begin("korbridge", false);
  apPassword = prefs.getString("ap_pass", "");
  if(apPassword.length() < 12) {
    char buf[25];
    snprintf(buf, sizeof(buf), "%08lX%08lX",
      (unsigned long)esp_random(), (unsigned long)esp_random());
    apPassword = String(buf);
    prefs.putString("ap_pass", apPassword);
  }
  prefs.end();

  apSsid = "KOR-Bridge-" + deviceId.substring(deviceId.length() - 6);
}

void resetWifiMachine() {
  wifiAttemptActive = false;
  openNetworkTried = false;
  wifiSlot = 0;
  nextWifiCycleAt = 0;
  attemptingSsid = "";
}

void stopProvisioning() {
  if(!provisioning) return;
  provisionServer.stop();
  WiFi.softAPdisconnect(true);
  provisioning = false;
  addLog("provisioning AP stopped");
}

void startProvisioning() {
  if(provisioning || pausedForMarauder || !runtimeEnabled) return;

  ensureProvisioningIdentity();
  WiFi.mode(WIFI_AP_STA);

  if(!WiFi.softAP(apSsid.c_str(), apPassword.c_str())) {
    addLog("failed to start provisioning AP");
    return;
  }

  provisionServer.begin();
  provisionServer.setNoDelay(true);
  provisioning = true;
  bridgeState = "provisioning";

  Serial.print(F("@KOR provisioning SSID="));
  Serial.print(apSsid);
  Serial.print(F(" password="));
  Serial.print(apPassword);
  Serial.print(F(" http://192.168.4.1:"));
  Serial.println(KOR_PROVISION_PORT);
}

void startWifiAttempt(const String& ssid, const String& password) {
  if(provisioning) WiFi.mode(WIFI_AP_STA);
  else WiFi.mode(WIFI_STA);

  WiFi.setAutoReconnect(true);
  WiFi.disconnect(false, false);
  delay(20);

  attemptingSsid = ssid;
  if(password.length() > 0) WiFi.begin(ssid.c_str(), password.c_str());
  else WiFi.begin(ssid.c_str());

  wifiAttemptActive = true;
  wifiAttemptStarted = millis();
  bridgeState = "wifi_connecting";
  addLog("Wi-Fi attempt: " + ssid);
}

bool tryBestOpenNetwork() {
  if(!allowOpenNetworks()) return false;

  const int count = WiFi.scanNetworks(false, true);
  int best = -1;
  int32_t bestRssi = -1000;

  for(int i = 0; i < count; ++i) {
    if(WiFi.encryptionType(i) == WIFI_AUTH_OPEN && WiFi.RSSI(i) > bestRssi) {
      best = i;
      bestRssi = WiFi.RSSI(i);
    }
  }

  if(best < 0) {
    WiFi.scanDelete();
    return false;
  }

  const String ssid = WiFi.SSID(best);
  WiFi.scanDelete();
  startWifiAttempt(ssid, "");
  return true;
}

void serviceWifi(uint32_t now) {
  if(WiFi.status() == WL_CONNECTED) {
    if(wifiAttemptActive) {
      wifiAttemptActive = false;
      bridgeState = "wifi_connected";
      addLog("Wi-Fi connected: " + WiFi.SSID());
    }
    if(provisioning) stopProvisioning();
    return;
  }

  if(wifiAttemptActive) {
    if(now - wifiAttemptStarted < KOR_WIFI_ATTEMPT_MS) return;
    addLog("Wi-Fi attempt failed: " + attemptingSsid);
    WiFi.disconnect(false, false);
    wifiAttemptActive = false;
    attemptingSsid = "";
    ++wifiSlot;
  }

  if((int32_t)(now - nextWifiCycleAt) < 0) return;

  while(wifiSlot < KOR_WIFI_SLOTS) {
    String ssid, password;
    if(loadWifiProfile(wifiSlot, ssid, password)) {
      startWifiAttempt(ssid, password);
      return;
    }
    ++wifiSlot;
  }

  if(!openNetworkTried) {
    openNetworkTried = true;
    if(tryBestOpenNetwork()) return;
  }

  if(!provisioning) startProvisioning();
  wifiSlot = 0;
  openNetworkTried = false;
  nextWifiCycleAt = now + KOR_WIFI_RETRY_CYCLE_MS;
}

void writeHttp(WiFiClient& client, int code, const char* type, const String& body) {
  client.print(F("HTTP/1.1 "));
  client.print(code);
  client.println(code == 200 ? F(" OK") : F(" Bad Request"));
  client.print(F("Content-Type: "));
  client.println(type);
  client.print(F("Content-Length: "));
  client.println(body.length());
  client.println(F("Connection: close"));
  client.println();
  client.print(body);
}

void handleProvisionConfigure(WiFiClient& client, const String& body) {
  DynamicJsonDocument doc(4096);
  if(deserializeJson(doc, body)) {
    writeHttp(client, 400, "application/json", "{\"ok\":false,\"error\":\"invalid_json\"}");
    return;
  }

  bool changed = false;

  if(doc.containsKey("ssid")) {
    const String ssid = doc["ssid"].as<String>();
    const String password = doc["password"] | "";
    if(!saveWifiProfile(ssid, password)) {
      writeHttp(client, 400, "application/json", "{\"ok\":false,\"error\":\"wifi_profile\"}");
      return;
    }
    changed = true;
  }

  prefs.begin("korbridge", false);

  if(doc.containsKey("relay_host")) {
    prefs.putString("relay_host", doc["relay_host"].as<String>());
    changed = true;
  }

  if(doc.containsKey("relay_port")) {
    const int port = doc["relay_port"].as<int>();
    if(port <= 0 || port > 65535) {
      prefs.end();
      writeHttp(client, 400, "application/json", "{\"ok\":false,\"error\":\"relay_port\"}");
      return;
    }
    prefs.putUShort("relay_port", (uint16_t)port);
    changed = true;
  }

  if(doc.containsKey("relay_token")) {
    const String token = doc["relay_token"].as<String>();
    if(token.length() < 24) {
      prefs.end();
      writeHttp(client, 400, "application/json", "{\"ok\":false,\"error\":\"relay_token\"}");
      return;
    }
    prefs.putString("relay_token", token);
    changed = true;
  }

  if(doc.containsKey("relay_ca")) {
    const String ca = doc["relay_ca"].as<String>();
    if(ca.indexOf("BEGIN CERTIFICATE") < 0) {
      prefs.end();
      writeHttp(client, 400, "application/json", "{\"ok\":false,\"error\":\"relay_ca\"}");
      return;
    }
    prefs.putString("relay_ca", ca);
    changed = true;
  }

  if(doc.containsKey("allow_open")) {
    prefs.putBool("allow_open", doc["allow_open"].as<bool>());
    changed = true;
  }

  if(doc.containsKey("enabled")) {
    runtimeEnabled = doc["enabled"].as<bool>();
    prefs.putBool("enabled", runtimeEnabled);
    changed = true;
  }

  prefs.end();

  if(changed) {
    loadRelayConfig();
    resetWifiMachine();
    nextRelayAttemptAt = 0;
  }

  writeHttp(client, 200, "application/json", "{\"ok\":true}");
}

void serviceProvisioning() {
  if(!provisioning) return;

  WiFiClient client = provisionServer.available();
  if(!client) return;

  client.setTimeout(250);
  String requestLine = client.readStringUntil('\n');
  requestLine.trim();

  int contentLength = 0;
  while(client.connected()) {
    String line = client.readStringUntil('\n');
    line.trim();
    if(line.length() == 0) break;
    if(line.startsWith("Content-Length:")) contentLength = line.substring(15).toInt();
  }

  if(requestLine.startsWith("GET /status ")) {
    writeHttp(client, 200, "application/json", KorBridge::statusJson());
    client.stop();
    return;
  }

  if(requestLine.startsWith("POST /configure ")) {
    if(contentLength <= 0 || contentLength > 4096) {
      writeHttp(client, 400, "application/json", "{\"ok\":false,\"error\":\"content_length\"}");
      client.stop();
      return;
    }

    String body;
    body.reserve(contentLength);
    const uint32_t deadline = millis() + 1500;

    while((int)body.length() < contentLength && (int32_t)(millis() - deadline) < 0) {
      while(client.available() && (int)body.length() < contentLength) body += (char)client.read();
      delay(1);
    }

    if((int)body.length() != contentLength) {
      writeHttp(client, 400, "application/json", "{\"ok\":false,\"error\":\"short_body\"}");
      client.stop();
      return;
    }

    handleProvisionConfigure(client, body);
    client.stop();
    return;
  }

  writeHttp(client, 400, "application/json", "{\"ok\":false,\"error\":\"route\"}");
  client.stop();
}

void ensureNtp() {
  if(ntpStarted) return;
  configTime(0, 0, "pool.ntp.org", "time.cloudflare.com");
  ntpStarted = true;
  bridgeState = "time_sync";
  addLog("NTP sync requested");
}

bool tlsTimeReady() {
  return time(nullptr) > 1700000000;
}

void fillStatus(JsonObject out) {
  out["device_id"] = deviceId;
  out["firmware"] = String(MARAUDER_VERSION) + "+kor-passive1";
  out["uptime_ms"] = millis();
  out["heap"] = ESP.getFreeHeap();
  out["bridge_state"] = bridgeState;
  out["relay_connected"] = relayClient.connected();
  out["provisioning"] = provisioning;
  out["rpc_enabled"] = false;
  out["wifi_profiles"] = wifiProfileCount();

  if(WiFi.status() == WL_CONNECTED) {
    out["wifi_ssid"] = WiFi.SSID();
    out["rssi"] = WiFi.RSSI();
    out["ip"] = WiFi.localIP().toString();
  } else {
    out["wifi_ssid"] = "";
    out["rssi"] = 0;
    out["ip"] = "";
  }
}

void sendJson(DynamicJsonDocument& doc) {
  if(!relayClient.connected()) return;
  serializeJson(doc, relayClient);
  relayClient.print('\n');
}

void sendHello() {
  DynamicJsonDocument doc(768);
  doc["type"] = "hello";
  doc["device_id"] = deviceId;
  doc["token"] = relayToken;
  doc["firmware"] = String(MARAUDER_VERSION) + "+kor-passive1";
  doc["mode"] = "passive";
  doc["rpc_enabled"] = false;
  sendJson(doc);
}

void scheduleRelayReconnect(const String& reason) {
  relayClient.stop();
  bridgeState = "relay_wait";
  addLog("relay disconnected: " + reason);
  nextRelayAttemptAt = millis() + relayBackoffMs;
  relayBackoffMs = min(relayBackoffMs * 2, KOR_RELAY_BACKOFF_MAX_MS);
}

void connectRelay(uint32_t now) {
  if(!relayConfigured()) {
    bridgeState = "relay_unconfigured";
    return;
  }

  ensureNtp();
  if(!tlsTimeReady()) {
    bridgeState = "time_sync";
    return;
  }

  if((int32_t)(now - nextRelayAttemptAt) < 0) return;

  relayClient.stop();
  relayClient.setCACert(relayCa.c_str());
  relayClient.setTimeout(2000);
  bridgeState = "relay_connecting";

  if(!relayClient.connect(relayHost.c_str(), relayPort)) {
    scheduleRelayReconnect("connect_failed");
    return;
  }

  relayBackoffMs = KOR_RELAY_BACKOFF_MIN_MS;
  nextRelayAttemptAt = 0;
  lastHeartbeatAt = 0;
  relayRx = "";
  bridgeState = "connected";
  addLog("secure outbound relay connected");
  sendHello();
}

void persistLastSeq() {
  prefs.begin("korbridge", false);
  prefs.putUInt("last_seq", lastAcceptedSeq);
  prefs.end();
}

void sendCommandError(uint32_t seq, const String& nonce, const char* error) {
  DynamicJsonDocument out(512);
  out["type"] = "command_result";
  out["seq"] = seq;
  out["nonce"] = nonce;
  out["ok"] = false;
  out["error"] = error;
  sendJson(out);
}

void handleRemoteCommand(const String& line) {
  DynamicJsonDocument in(1024);
  if(deserializeJson(in, line)) {
    addLog("relay message rejected: invalid_json");
    return;
  }

  const char* type = in["type"] | "";
  if(strcmp(type, "command") != 0) return;

  const uint32_t seq = in["seq"] | 0U;
  const String nonce = in["nonce"] | "";
  const String command = in["command"] | "";

  if(seq == 0 || seq <= lastAcceptedSeq) {
    sendCommandError(seq, nonce, "replay_or_sequence");
    return;
  }

  if(nonce.length() < 8 || nonce.length() > 96) {
    sendCommandError(seq, nonce, "nonce");
    return;
  }

  const bool allowed =
    command == "ping" ||
    command == "status" ||
    command == "logs.tail" ||
    command == "bridge.info";

  if(!allowed) {
    sendCommandError(seq, nonce, "read_only_allowlist");
    return;
  }

  lastAcceptedSeq = seq;
  persistLastSeq();

  DynamicJsonDocument out(2048);
  out["type"] = "command_result";
  out["seq"] = seq;
  out["nonce"] = nonce;
  out["ok"] = true;

  if(command == "ping") {
    out["payload"]["pong"] = true;
  } else if(command == "status") {
    JsonObject payload = out.createNestedObject("payload");
    fillStatus(payload);
  } else if(command == "bridge.info") {
    JsonObject payload = out.createNestedObject("payload");
    payload["transport"] = "outbound_tls";
    payload["inbound_listener"] = false;
    payload["rpc_enabled"] = false;
    payload["mode"] = "passive_read_only";
    payload["version"] = "kor-passive1";
  } else if(command == "logs.tail") {
    JsonObject payload = out.createNestedObject("payload");
    JsonArray items = payload.createNestedArray("items");
    const uint8_t count = min((uint8_t)8, logCount);
    const uint8_t first = (logHead + KOR_LOG_SLOTS - count) % KOR_LOG_SLOTS;
    for(uint8_t i = 0; i < count; ++i) items.add(logs[(first + i) % KOR_LOG_SLOTS]);
  }

  sendJson(out);
}

void serviceRelayInput() {
  while(relayClient.available()) {
    const char c = (char)relayClient.read();

    if(c == '\n') {
      relayRx.trim();
      if(relayRx.length() > 0) handleRemoteCommand(relayRx);
      relayRx = "";
      continue;
    }

    if(c == '\r') continue;

    if(relayRx.length() >= KOR_MAX_RELAY_LINE) {
      relayRx = "";
      addLog("relay message dropped: too_large");
      continue;
    }

    relayRx += c;
  }
}

void sendHeartbeat(uint32_t now) {
  if(now - lastHeartbeatAt < KOR_HEARTBEAT_MS) return;
  lastHeartbeatAt = now;

  DynamicJsonDocument doc(768);
  doc["type"] = "heartbeat";
  JsonObject payload = doc.createNestedObject("status");
  fillStatus(payload);
  sendJson(doc);
}

void serviceRelay(uint32_t now) {
  if(!relayClient.connected()) {
    connectRelay(now);
    return;
  }

  bridgeState = "connected";
  serviceRelayInput();

  if(!relayClient.connected()) {
    scheduleRelayReconnect("socket_closed");
    return;
  }

  sendHeartbeat(now);
}

void setRuntimeEnabled(bool value) {
  runtimeEnabled = value;
  prefs.begin("korbridge", false);
  prefs.putBool("enabled", value);
  prefs.end();

  if(!value) {
    relayClient.stop();
    stopProvisioning();
    bridgeState = "disabled";
    addLog("bridge disabled");
    return;
  }

  bridgeState = "idle";
  resetWifiMachine();
  nextRelayAttemptAt = 0;
  addLog("bridge enabled");
}

void printRelayConfig() {
  Serial.print(F("relay_host: "));
  Serial.println(relayHost.length() ? relayHost : F("<unset>"));
  Serial.print(F("relay_port: "));
  Serial.println(relayPort);
  Serial.print(F("relay_token_set: "));
  Serial.println(relayToken.length() >= 24 ? F("yes") : F("no"));
  Serial.print(F("relay_ca_set: "));
  Serial.println(relayCa.indexOf("BEGIN CERTIFICATE") >= 0 ? F("yes") : F("no"));
}
}

bool KorBridge::enabled() {
  prefs.begin("korbridge", true);
  const bool value = prefs.getBool("enabled", false);
  prefs.end();
  return value;
}

void KorBridge::begin() {
  deviceId = makeDeviceId();
  ensureProvisioningIdentity();
  loadRelayConfig();
  runtimeEnabled = enabled();
  bridgeState = runtimeEnabled ? "idle" : "disabled";

  if(runtimeEnabled) {
    resetWifiMachine();
    addLog("passive bridge initialized; RPC disabled");
  }
}

void KorBridge::loop(bool marauderBusy) {
  if(!runtimeEnabled) return;

  if(marauderBusy) {
    if(!pausedForMarauder) {
      pausedForMarauder = true;
      relayClient.stop();
      stopProvisioning();
      bridgeState = "paused_marauder";
    }
    return;
  }

  if(pausedForMarauder) {
    pausedForMarauder = false;
    bridgeState = "resume";
    nextRelayAttemptAt = 0;
    if(WiFi.status() != WL_CONNECTED) resetWifiMachine();
    addLog("bridge resumed");
  }

  const uint32_t now = millis();
  serviceWifi(now);

  if(WiFi.status() == WL_CONNECTED) serviceRelay(now);
  else serviceProvisioning();
}

String KorBridge::statusJson() {
  DynamicJsonDocument doc(1024);
  JsonObject root = doc.to<JsonObject>();
  fillStatus(root);
  String out;
  serializeJson(doc, out);
  return out;
}

bool KorBridge::handleCli(LinkedList<String>& args) {
  if(args.size() == 0 || args.get(0) != "kor") return false;

  if(args.size() == 1 || args.get(1) == "help") {
    Serial.println(F("kor status"));
    Serial.println(F("kor bridge on|off"));
    Serial.println(F("kor wifi list"));
    Serial.println(F("kor wifi add <ssid> [password]"));
    Serial.println(F("kor wifi remove <index>"));
    Serial.println(F("kor open on|off"));
    Serial.println(F("kor relay show"));
    Serial.println(F("kor relay set <host> <port> <token>"));
    Serial.println(F("kor provision"));
    Serial.println(F("kor rpc"));
    return true;
  }

  const String sub = args.get(1);

  if(sub == "status") {
    Serial.print(F("@KOR "));
    Serial.println(statusJson());
    return true;
  }

  if(sub == "bridge" && args.size() >= 3) {
    if(args.get(2) == "on") setRuntimeEnabled(true);
    else if(args.get(2) == "off") setRuntimeEnabled(false);
    else Serial.println(F("ERR: use on|off"));
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
      if(saveWifiProfile(ssid, password)) {
        resetWifiMachine();
        Serial.println(F("OK"));
      } else {
        Serial.println(F("ERR"));
      }
      return true;
    }

    if(action == "remove" && args.size() >= 4) {
      const int idx = args.get(3).toInt();
      Serial.println(removeWifiProfile((uint8_t)idx) ? F("OK") : F("ERR"));
      return true;
    }
  }

  if(sub == "open" && args.size() >= 3) {
    const bool on = args.get(2) == "on";
    const bool off = args.get(2) == "off";
    if(!on && !off) {
      Serial.println(F("ERR: use on|off"));
      return true;
    }

    prefs.begin("korbridge", false);
    prefs.putBool("allow_open", on);
    prefs.end();
    resetWifiMachine();
    Serial.println(on ? F("Open-network fallback enabled") : F("Open-network fallback disabled"));
    return true;
  }

  if(sub == "relay" && args.size() >= 3) {
    const String action = args.get(2);

    if(action == "show") {
      printRelayConfig();
      return true;
    }

    if(action == "set" && args.size() >= 6) {
      const String host = args.get(3);
      const int port = args.get(4).toInt();
      const String token = args.get(5);

      if(host.length() == 0 || port <= 0 || port > 65535 || token.length() < 24) {
        Serial.println(F("ERR: relay set <host> <port> <token>=24+ chars"));
        return true;
      }

      prefs.begin("korbridge", false);
      prefs.putString("relay_host", host);
      prefs.putUShort("relay_port", (uint16_t)port);
      prefs.putString("relay_token", token);
      prefs.end();

      loadRelayConfig();
      nextRelayAttemptAt = 0;
      Serial.println(F("OK; CA certificate must be provisioned locally before TLS connects"));
      return true;
    }
  }

  if(sub == "provision") {
    startProvisioning();
    return true;
  }

  if(sub == "rpc") {
    Serial.println(F("RPC transport is disabled in passive milestone; Expansion Protocol is next."));
    return true;
  }

  Serial.println(F("ERR: unknown kor command"));
  return true;
}

#endif
