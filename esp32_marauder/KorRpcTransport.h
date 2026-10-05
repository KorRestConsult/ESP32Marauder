#pragma once

#ifdef MARAUDER_KOR_BRIDGE

#include <Arduino.h>

typedef void (*KorRpcRxCallback)(const uint8_t* data, size_t len, void* context);

class KorRpcTransport {
public:
  static void begin(bool locallyAllowed);
  static void loop();

  static bool locallyAllowed();
  static void setLocallyAllowed(bool allowed);

  static bool requestExpansion();
  static void close();
  static bool sendRpc(const uint8_t* data, size_t len);

  static bool ownsUart();
  static bool connected();
  static bool marauderMode();
  static uint32_t marauderBaud();
  static const char* stateName();

  static void setRxCallback(KorRpcRxCallback callback, void* context);
};

#endif
