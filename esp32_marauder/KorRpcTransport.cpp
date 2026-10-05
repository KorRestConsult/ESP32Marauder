#include "KorRpcTransport.h"

#ifdef MARAUDER_KOR_BRIDGE

#include "kor_expansion_protocol.h"

namespace {

constexpr uint32_t KOR_RPC_BAUD = 230400;
constexpr uint32_t KOR_MARAUDER_LEGACY_BAUD = 115200;
constexpr uint32_t KOR_MARAUDER_FAST_BAUD = 230400;
constexpr uint32_t KOR_HEARTBEAT_INTERVAL_MS = 180;
constexpr uint32_t KOR_MARAUDER_PROBE_MS = 650;

enum class KorRpcState : uint8_t {
  Disabled,
  Marauder,
  RpcActive,
};

KorRpcState state = KorRpcState::Disabled;
bool local_allowed = false;
uint32_t marauder_baud = KOR_MARAUDER_LEGACY_BAUD;
uint32_t last_protocol_activity = 0;
KorRpcRxCallback rx_callback = nullptr;
void* rx_context = nullptr;

void setBaud(uint32_t baud) {
  Serial.flush();
  Serial.updateBaudRate(baud);
  delay(2);
}

void drainSerial() {
  while(Serial.available()) Serial.read();
}

size_t serialReceive(uint8_t* data, size_t len, void*) {
  size_t got = 0;
  const uint32_t started = millis();

  while(got < len && (millis() - started) < EXPANSION_PROTOCOL_TIMEOUT_MS) {
    while(Serial.available() && got < len) {
      data[got++] = (uint8_t)Serial.read();
    }
    if(got < len) delay(1);
  }

  return got;
}

size_t serialSend(const uint8_t* data, size_t len, void*) {
  const size_t sent = Serial.write(data, len);
  Serial.flush();
  return sent;
}

bool sendFrame(const ExpansionFrame& frame) {
  const bool ok =
    expansion_protocol_encode(&frame, serialSend, nullptr) == ExpansionProtocolStatusOk;
  if(ok) last_protocol_activity = millis();
  return ok;
}

bool receiveFrame(ExpansionFrame& frame) {
  memset(&frame, 0, sizeof(frame));
  const bool ok =
    expansion_protocol_decode(&frame, serialReceive, nullptr) == ExpansionProtocolStatusOk;
  if(ok) last_protocol_activity = millis();
  return ok;
}

bool sendStatusOk() {
  ExpansionFrame frame{};
  frame.header.type = ExpansionFrameTypeStatus;
  frame.content.status.error = ExpansionFrameErrorNone;
  return sendFrame(frame);
}

bool sendHeartbeat() {
  ExpansionFrame frame{};
  frame.header.type = ExpansionFrameTypeHeartbeat;
  return sendFrame(frame);
}

bool sendBaudRequest(uint32_t baud) {
  ExpansionFrame frame{};
  frame.header.type = ExpansionFrameTypeBaudRate;
  frame.content.baud_rate.baud = baud;
  return sendFrame(frame);
}

bool sendControl(ExpansionFrameControlCommand command) {
  ExpansionFrame frame{};
  frame.header.type = ExpansionFrameTypeControl;
  frame.content.control.command = command;
  return sendFrame(frame);
}

bool isStatusOk(const ExpansionFrame& frame) {
  return frame.header.type == ExpansionFrameTypeStatus &&
         frame.content.status.error == ExpansionFrameErrorNone;
}

void deliverRpc(const uint8_t* data, size_t len) {
  if(rx_callback && len) rx_callback(data, len, rx_context);
}

bool handleIncomingFrame(const ExpansionFrame& frame) {
  if(frame.header.type == ExpansionFrameTypeData) {
    if(!sendStatusOk()) return false;
    deliverRpc(frame.content.data.bytes, frame.content.data.size);
    return true;
  }

  if(frame.header.type == ExpansionFrameTypeHeartbeat) {
    return sendHeartbeat();
  }

  if(frame.header.type == ExpansionFrameTypeStatus) {
    return frame.content.status.error == ExpansionFrameErrorNone;
  }

  return false;
}

void enterMarauder(uint32_t baud) {
  setBaud(baud);
  drainSerial();
  marauder_baud = baud;
  state = local_allowed ? KorRpcState::Marauder : KorRpcState::Disabled;
}

bool waitForWakeAt(uint32_t baud, uint32_t timeoutMs) {
  setBaud(baud);
  drainSerial();

  const uint32_t started = millis();
  while((millis() - started) < timeoutMs) {
    while(Serial.available()) {
      const uint8_t b = (uint8_t)Serial.read();
      if(b == (uint8_t)'w') {
        marauder_baud = baud;
        state = KorRpcState::Marauder;
        return true;
      }
    }
    delay(1);
  }

  return false;
}

void detectMarauderAfterExpansionLoss() {
  // Momentum's legacy companion for Marauder 1.7.0 uses 115200.
  if(waitForWakeAt(KOR_MARAUDER_LEGACY_BAUD, KOR_MARAUDER_PROBE_MS)) return;

  // Newer mayhem_marauder uses 230400 and also transmits 'w' twice at startup.
  if(waitForWakeAt(KOR_MARAUDER_FAST_BAUD, KOR_MARAUDER_PROBE_MS)) return;

  // Fail safe for the user's known-good Marauder 1.7.0.
  enterMarauder(KOR_MARAUDER_LEGACY_BAUD);
}

bool waitForStatusAck() {
  const uint32_t started = millis();

  while((millis() - started) < EXPANSION_PROTOCOL_TIMEOUT_MS) {
    if(!Serial.available()) {
      delay(1);
      continue;
    }

    ExpansionFrame frame{};
    if(!receiveFrame(frame)) return false;

    if(isStatusOk(frame)) return true;

    if(frame.header.type == ExpansionFrameTypeData) {
      if(!sendStatusOk()) return false;
      deliverRpc(frame.content.data.bytes, frame.content.data.size);
      continue;
    }

    if(frame.header.type == ExpansionFrameTypeHeartbeat) {
      if(!sendHeartbeat()) return false;
      continue;
    }

    return false;
  }

  return false;
}

bool negotiateExpansion() {
  setBaud(EXPANSION_PROTOCOL_DEFAULT_BAUD_RATE);
  drainSerial();

  // Official Momentum expansion test uses 0xAA to create the falling edge
  // that signals module presence on Flipper RX.
  const uint8_t presence = 0xAA;
  Serial.write(&presence, 1);
  Serial.flush();

  ExpansionFrame frame{};
  if(!receiveFrame(frame) || frame.header.type != ExpansionFrameTypeHeartbeat) return false;

  if(!sendBaudRequest(KOR_RPC_BAUD)) return false;
  if(!receiveFrame(frame) || !isStatusOk(frame)) return false;

  setBaud(KOR_RPC_BAUD);
  delay(EXPANSION_PROTOCOL_BAUD_CHANGE_DT_MS);

  if(!sendControl(ExpansionFrameControlCommandStartRpc)) return false;
  if(!receiveFrame(frame) || !isStatusOk(frame)) return false;

  state = KorRpcState::RpcActive;
  last_protocol_activity = millis();
  return true;
}

void expansionLost() {
  state = KorRpcState::Marauder;
  detectMarauderAfterExpansionLoss();
}

} // namespace

void KorRpcTransport::begin(bool locallyAllowedValue) {
  local_allowed = locallyAllowedValue;
  enterMarauder(KOR_MARAUDER_LEGACY_BAUD);
}

void KorRpcTransport::loop() {
  if(state != KorRpcState::RpcActive) return;

  if(Serial.available()) {
    ExpansionFrame frame{};
    if(!receiveFrame(frame) || !handleIncomingFrame(frame)) {
      expansionLost();
      return;
    }
  }

  if((millis() - last_protocol_activity) >= KOR_HEARTBEAT_INTERVAL_MS) {
    if(!sendHeartbeat()) {
      expansionLost();
      return;
    }

    ExpansionFrame reply{};
    if(!receiveFrame(reply) || reply.header.type != ExpansionFrameTypeHeartbeat) {
      if(reply.header.type == ExpansionFrameTypeData) {
        if(!sendStatusOk()) {
          expansionLost();
          return;
        }
        deliverRpc(reply.content.data.bytes, reply.content.data.size);
      } else {
        expansionLost();
        return;
      }
    }
  }
}

bool KorRpcTransport::locallyAllowed() {
  return local_allowed;
}

void KorRpcTransport::setLocallyAllowed(bool allowed) {
  local_allowed = allowed;
  if(!allowed) {
    close();
    state = KorRpcState::Disabled;
  } else if(state == KorRpcState::Disabled) {
    enterMarauder(KOR_MARAUDER_LEGACY_BAUD);
  }
}

bool KorRpcTransport::requestExpansion() {
  if(!local_allowed) return false;
  if(state == KorRpcState::RpcActive) return true;

  if(negotiateExpansion()) return true;

  enterMarauder(KOR_MARAUDER_LEGACY_BAUD);
  return false;
}

void KorRpcTransport::close() {
  if(state == KorRpcState::RpcActive) {
    if(sendControl(ExpansionFrameControlCommandStopRpc)) {
      ExpansionFrame response{};
      receiveFrame(response);
    }
  }

  enterMarauder(KOR_MARAUDER_LEGACY_BAUD);
}

bool KorRpcTransport::sendRpc(const uint8_t* data, size_t len) {
  if(state != KorRpcState::RpcActive || !data || len == 0) return false;

  size_t offset = 0;
  while(offset < len) {
    const size_t chunk =
      min((size_t)EXPANSION_PROTOCOL_MAX_DATA_SIZE, len - offset);

    ExpansionFrame frame{};
    frame.header.type = ExpansionFrameTypeData;
    frame.content.data.size = (uint8_t)chunk;
    memcpy(frame.content.data.bytes, data + offset, chunk);

    if(!sendFrame(frame) || !waitForStatusAck()) {
      expansionLost();
      return false;
    }

    offset += chunk;
  }

  return true;
}

bool KorRpcTransport::ownsUart() {
  return state == KorRpcState::RpcActive;
}

bool KorRpcTransport::connected() {
  return state == KorRpcState::RpcActive;
}

bool KorRpcTransport::marauderMode() {
  return state == KorRpcState::Marauder;
}

uint32_t KorRpcTransport::marauderBaud() {
  return marauder_baud;
}

const char* KorRpcTransport::stateName() {
  switch(state) {
    case KorRpcState::Disabled:
      return "disabled";
    case KorRpcState::Marauder:
      return "marauder";
    case KorRpcState::RpcActive:
      return "rpc";
    default:
      return "unknown";
  }
}

void KorRpcTransport::setRxCallback(KorRpcRxCallback callback, void* context) {
  rx_callback = callback;
  rx_context = context;
}

#endif
