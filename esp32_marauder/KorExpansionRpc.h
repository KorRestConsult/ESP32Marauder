#pragma once

#ifdef MARAUDER_KOR_RPC

#include <Arduino.h>

class KorExpansionRpc {
public:
  static void begin();
  static bool open();
  static void close();
  static bool active();
  static bool ownsUart();
  static bool sendRequest(const uint8_t* data, size_t size);
  static void loop();
  static size_t read(uint8_t* data, size_t capacity);
};

#endif
