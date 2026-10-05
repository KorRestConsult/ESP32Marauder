#include "KorExpansionRpc.h"

#ifdef MARAUDER_KOR_RPC

#include "kor_expansion_protocol.h"

#include <freertos/FreeRTOS.h>
#include <freertos/stream_buffer.h>

namespace {

constexpr uint32_t KOR_RPC_BAUD = 230400;
constexpr uint32_t KOR_MARAUDER_BAUD = 115200;
constexpr uint32_t KOR_FRAME_TIMEOUT_MS = 220;
constexpr uint32_t KOR_HEARTBEAT_MS = 150;

StreamBufferHandle_t response_buffer = nullptr;
bool rpc_active = false;
bool uart_owned = false;
uint32_t last_activity = 0;

size_t serialReceive(uint8_t* data, size_t len, void*) {
  size_t got = 0;
  const uint32_t started = millis();

  while(got < len && millis() - started < KOR_FRAME_TIMEOUT_MS) {
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
  last_activity = millis();
  return sent;
}

bool sendFrame(const ExpansionFrame& frame) {
  return expansion_protocol_encode(&frame, serialSend, nullptr) == ExpansionProtocolStatusOk;
}

bool receiveFrame(ExpansionFrame& frame) {
  memset(&frame, 0, sizeof(frame));
  const bool ok =
    expansion_protocol_decode(&frame, serialReceive, nullptr) == ExpansionProtocolStatusOk;
  if(ok) last_activity = millis();
  return ok;
}

bool isOk(const ExpansionFrame& frame) {
  return frame.header.type == ExpansionFrameTypeStatus &&
         frame.content.status.error == ExpansionFrameErrorNone;
}

bool sendHeartbeat() {
  ExpansionFrame frame{};
  frame.header.type = ExpansionFrameTypeHeartbeat;
  return sendFrame(frame);
}

bool sendStatus(ExpansionFrameError error = ExpansionFrameErrorNone) {
  ExpansionFrame frame{};
  frame.header.type = ExpansionFrameTypeStatus;
  frame.content.status.error = error;
  return sendFrame(frame);
}

bool sendBaud(uint32_t baud) {
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

bool sendData(const uint8_t* data, size_t size) {
  if(size == 0 || size > EXPANSION_PROTOCOL_MAX_DATA_SIZE) return false;

  ExpansionFrame frame{};
  frame.header.type = ExpansionFrameTypeData;
  frame.content.data.size = (uint8_t)size;
  memcpy(frame.content.data.bytes, data, size);
  return sendFrame(frame);
}

bool firstByteLooksLikeMarauderCli() {
  if(!Serial.available()) return false;
  const int value = Serial.peek();
  return value == '\r' || value == '\n' || (value >= 0x20 && value <= 0x7E);
}

void releaseUart() {
  rpc_active = false;
  uart_owned = false;
  Serial.updateBaudRate(KOR_MARAUDER_BAUD);
}

bool handleIncomingFrame(const ExpansionFrame& frame) {
  if(frame.header.type == ExpansionFrameTypeData) {
    if(!sendStatus()) return false;
    if(frame.content.data.size) {
      xStreamBufferSend(
        response_buffer,
        frame.content.data.bytes,
        frame.content.data.size,
        pdMS_TO_TICKS(20));
    }
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

}  // namespace

void KorExpansionRpc::begin() {
  if(!response_buffer) response_buffer = xStreamBufferCreate(8192, 1);
}

bool KorExpansionRpc::open() {
  begin();
  if(rpc_active) return true;

  if(firstByteLooksLikeMarauderCli()) return false;

  uart_owned = true;
  Serial.updateBaudRate(EXPANSION_PROTOCOL_DEFAULT_BAUD_RATE);
  while(Serial.available()) Serial.read();

  // Momentum Expansion presence pulse.
  const uint8_t presence = 0xAA;
  Serial.write(&presence, 1);
  Serial.flush();

  ExpansionFrame frame{};
  if(!receiveFrame(frame) || frame.header.type != ExpansionFrameTypeHeartbeat) {
    releaseUart();
    return false;
  }

  if(!sendBaud(KOR_RPC_BAUD) || !receiveFrame(frame) || !isOk(frame)) {
    releaseUart();
    return false;
  }

  Serial.updateBaudRate(KOR_RPC_BAUD);
  delay(EXPANSION_PROTOCOL_BAUD_CHANGE_DT_MS);

  if(!sendControl(ExpansionFrameControlCommandStartRpc) ||
     !receiveFrame(frame) ||
     !isOk(frame)) {
    releaseUart();
    return false;
  }

  rpc_active = true;
  last_activity = millis();
  return true;
}

void KorExpansionRpc::close() {
  if(rpc_active) {
    ExpansionFrame frame{};
    sendControl(ExpansionFrameControlCommandStopRpc);
    receiveFrame(frame);
  }
  releaseUart();
}

bool KorExpansionRpc::active() {
  return rpc_active;
}

bool KorExpansionRpc::ownsUart() {
  return uart_owned;
}

bool KorExpansionRpc::sendRequest(const uint8_t* data, size_t size) {
  if(!rpc_active || !data || size == 0) return false;

  size_t offset = 0;
  while(offset < size) {
    const size_t chunk =
      min(size - offset, (size_t)EXPANSION_PROTOCOL_MAX_DATA_SIZE);

    if(!sendData(data + offset, chunk)) {
      close();
      return false;
    }

    ExpansionFrame ack{};
    if(!receiveFrame(ack) || !isOk(ack)) {
      close();
      return false;
    }

    offset += chunk;
  }

  return true;
}

void KorExpansionRpc::loop() {
  if(!rpc_active) return;

  // If the Flipper application has taken UART back, fail closed and return
  // ownership to stock Marauder. Bytes are intentionally left untouched.
  if(firstByteLooksLikeMarauderCli()) {
    releaseUart();
    return;
  }

  if(Serial.available()) {
    ExpansionFrame frame{};
    if(!receiveFrame(frame) || !handleIncomingFrame(frame)) {
      releaseUart();
    }
    return;
  }

  if(millis() - last_activity >= KOR_HEARTBEAT_MS) {
    ExpansionFrame frame{};
    if(!sendHeartbeat() || !receiveFrame(frame) || !handleIncomingFrame(frame)) {
      releaseUart();
    }
  }
}

size_t KorExpansionRpc::read(uint8_t* data, size_t capacity) {
  if(!response_buffer || !data || capacity == 0) return 0;
  return xStreamBufferReceive(response_buffer, data, capacity, 0);
}

#endif
