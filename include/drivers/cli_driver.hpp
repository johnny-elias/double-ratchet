#pragma once

#include <cstdlib>
#include <string>
#include <sys/ioctl.h>
#include <atomic>
#include <iostream>

class CLIDriver {
public:
  CLIDriver();
  void init();
  void clear();
  void print_info(std::string message);
  void print_success(std::string message);
  void print_warning(std::string message);
  void print_left(std::string message);
  void print_right(std::string message);

private:
  struct winsize size;

private:
  std::atomic<bool> shutting_down = false;
public:
  std::string read_input() {
    std::string line;
    std::getline(std::cin, line);
    if (shutting_down) return "";
    return line;
  }
  void notify_shutdown() {
    shutting_down = true;
    std::cin.setstate(std::ios::eofbit);   // force getline to return
  }
};
