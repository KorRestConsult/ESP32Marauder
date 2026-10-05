#pragma once

#ifdef MARAUDER_KOR_BRIDGE

#include <Arduino.h>
#include <LinkedList.h>

class KorBridge {
public:
  static bool enabled();
  static void begin();
  static void loop(bool marauderBusy);
  static bool handleCli(LinkedList<String>& args);
  static String statusJson();
};

#endif
