#pragma once

#ifdef MARAUDER_KOR_BRIDGE

#include <Arduino.h>

class KorRpcTransport {
public:
  static bool attached();
  static bool attach();
  static void detach();
  static void loop();

  static size_t write(const uint8_t* data, size_t length);
  static size_t read(uint8_t* data, size_t capacity);
  static size_t available();
};

#endif
