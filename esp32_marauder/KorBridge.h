#pragma once

#ifdef MARAUDER_KOR_BRIDGE

#include <Arduino.h>
#include <LinkedList.h>

class KorBridge {
public:
  static bool enabled();
  static bool active();
  static void begin();
  static void loop();
  static bool handleCli(LinkedList<String>& args);
};

#endif
