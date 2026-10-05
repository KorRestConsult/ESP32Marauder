#include "KorBridge.h"

#ifdef MARAUDER_KOR_BRIDGE

#include <WiFi.h>
#include <Preferences.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/stream_buffer.h>

#include "settings.h"
#include "kor_expansion_protocol.h"

extern Settings settings_obj;

namespace {
constexpr uint16_t KOR_LOCAL_PORT = 8765;
constexpr uint32_t KOR_RPC_BAUD = 115200;
constexpr uint32_t KOR_FRAME_TIMEOUT_MS = 180;
constexpr uint32_t KOR_WIFI_RETRY_MS = 10000;

Preferences prefs;
WiFiServer server(KOR_LOCAL_PORT);
WiFiClient client;

StreamBufferHandle_t to_flipper = nullptr;
StreamBufferHandle_t from_flipper = nullptr;
TaskHandle_t rpc_task_handle = nullptr;

bool bridge_active = false;
bool client_authed = false;
String auth_line;
uint32_t last_wifi_attempt = 0;
String device_id;

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
  ExpansionFrame f{};
  f.header.type = ExpansionFrameTypeData;
  f.content.data.size = len;
  memcpy(f.content.data.bytes, data, len);
  return sendFrame(f);
}

bool startRpcSession() {
  Serial.updateBaudRate(EXPANSION_PROTOCOL_DEFAULT_BAUD_RATE);
  while(Serial.available()) Serial.read();

  // Presence pulse used by known ESP32 expansion-module implementations.
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

String makeDeviceId() {
  uint64_t mac = ESP.getEfuseMac();
  char buf[17];
  snprintf(buf, sizeof(buf), "%04X%08X", (uint16_t)(mac >> 32), (uint32_t)mac);
  return String(buf);
}

String ensureToken() {
  prefs.begin("korbridge", false);
  String token = prefs.getString("token", "");
  if(token.length() < 16) {
    uint64_t mac = ESP.getEfuseMac();
    char buf[40];
    snprintf(
      buf,
      sizeof(buf),
      "%08lX%08lX%08lX",
      (unsigned long)(mac >> 32),
      (unsigned long)mac,
      (unsigned long)esp_random());
    token = String(buf);
    prefs.putString("token", token);
  }
  prefs.end();
  return token;
}

bool connectSavedWifi() {
  WiFi.mode(WIFI_STA);

  const uint8_t count = settings_obj.getSavedWifiCount();
  for(uint8_t i = 0; i < count; ++i) {
    String ssid;
    String password;
    if(!settings_obj.loadSavedWifiCredential(i, ssid, password)) continue;
    if(ssid.length() == 0) continue;

    WiFi.disconnect(true, true);
    delay(50);
    WiFi.begin(ssid.c_str(), password.c_str());

    const uint32_t start = millis();
    while(WiFi.status() != WL_CONNECTED && millis() - start < 7000) delay(100);

    if(WiFi.status() == WL_CONNECTED) {
      settings_obj.markSavedWifiSuccessful(i);
      server.begin();
      server.setNoDelay(true);
      return true;
    }
  }

  return false;
}

void closeClient() {
  if(client) client.stop();
  client_authed = false;
  auth_line = "";
}

void pumpClient() {
  if(!client || !client.connected()) {
    closeClient();
    WiFiClient incoming = server.available();
    if(incoming) {
      client = incoming;
      client.setNoDelay(true);
    } else {
      return;
    }
  }

  String token;
  prefs.begin("korbridge", true);
  token = prefs.getString("token", "");
  prefs.end();

  if(!client_authed) {
    while(client.available()) {
      char c = (char)client.read();
      if(c == '\n') {
        auth_line.trim();
        String expected = "KOR1 " + token;
        if(auth_line == expected) {
          client_authed = true;
          client.print("OK KOR1 ");
          client.println(device_id);
        } else {
          client.println("ERR AUTH");
          closeClient();
        }
        auth_line = "";
        break;
      }

      if(c != '\r') {
        auth_line += c;
        if(auth_line.length() > 160) {
          closeClient();
          return;
        }
      }
    }
    return;
  }

  uint8_t buf[256];

  while(client.available()) {
    size_t n = client.read(buf, sizeof(buf));
    if(n > 0) xStreamBufferSend(to_flipper, buf, n, pdMS_TO_TICKS(20));
  }

  size_t n = xStreamBufferReceive(from_flipper, buf, sizeof(buf), 0);
  if(n > 0) {
    if(client.write(buf, n) != n) closeClient();
  }
}

void printStatus() {
  prefs.begin("korbridge", true);
  bool en = prefs.getBool("enabled", false);
  String token = prefs.getString("token", "");
  prefs.end();

  Serial.println(F("@KOR:{"));
  Serial.print(F("  mode: "));
  Serial.println(en ? F("bridge") : F("marauder"));
  Serial.print(F("  device: "));
  Serial.println(makeDeviceId());
  Serial.print(F("  wifi_profiles: "));
  Serial.println(settings_obj.getSavedWifiCount());
  Serial.print(F("  token_set: "));
  Serial.println(token.length() >= 16 ? F("yes") : F("no"));
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
  settings_obj.begin();
  device_id = makeDeviceId();
  ensureToken();

  to_flipper = xStreamBufferCreate(4096, 1);
  from_flipper = xStreamBufferCreate(4096, 1);

  connectSavedWifi();

  xTaskCreate(
    rpcTask,
    "kor_rpc",
    6144,
    nullptr,
    2,
    &rpc_task_handle);
}

void KorBridge::loop() {
  if(WiFi.status() != WL_CONNECTED) {
    if(millis() - last_wifi_attempt >= KOR_WIFI_RETRY_MS) {
      last_wifi_attempt = millis();
      closeClient();
      connectSavedWifi();
    }
    delay(5);
    return;
  }

  pumpClient();
  delay(1);
}

bool KorBridge::handleCli(LinkedList<String>& args) {
  if(args.size() == 0 || args.get(0) != "kor") return false;

  if(args.size() == 1 || args.get(1) == "help") {
    Serial.println(F("kor status"));
    Serial.println(F("kor bridge on|off"));
    Serial.println(F("kor wifi list"));
    Serial.println(F("kor wifi add <ssid> <password>"));
    Serial.println(F("kor wifi remove <index>"));
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
      const uint8_t count = settings_obj.getSavedWifiCount();
      for(uint8_t i = 0; i < count; ++i) {
        String ssid, password;
        if(settings_obj.loadSavedWifiCredential(i, ssid, password)) {
          Serial.print(i);
          Serial.print(F(": "));
          Serial.println(ssid);
        }
      }
      return true;
    }

    if(action == "add" && args.size() >= 4) {
      String ssid = args.get(3);
      String password = args.size() >= 5 ? args.get(4) : "";
      WifiCredentialSaveResult result = settings_obj.saveWifiCredential(ssid, password);
      Serial.println(result == WIFI_CREDENTIAL_ERROR ? F("ERR") : F("OK"));
      return true;
    }

    if(action == "remove" && args.size() >= 4) {
      int idx = args.get(3).toInt();
      Serial.println(settings_obj.removeSavedWifiCredential((uint8_t)idx) ? F("OK") : F("ERR"));
      return true;
    }
  }

  if(sub == "token" && args.size() >= 3) {
    String token = args.get(2);
    if(token.length() < 16) {
      Serial.println(F("ERR: token must be at least 16 chars"));
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
