/**
* @file ui.h
* @author saul
* @brief ui header
*
*/

#ifndef UI_H
#define UI_H

#include <stdio.h>
#include <windows.h>

/**
  * @brief UI context. Snuck into pcap_loop() through the user_data
  */
typedef struct {
  FILE *output_file;
  unsigned long packets_counted;
  unsigned long max_packets;
  unsigned long num_eth;
  unsigned long num_ip;
  unsigned long num_tcp;
  int active; // flag for UI active state
  int listen_complete; // flag for listening active state
} ui_context;

void init_ui(ui_context *ctx);
void start_ui(ui_context *ctx);
void stop_ui(void);
void update_ui_stats(ui_context *ctx);

/**
* @brief toggles cursor for UI rendering
*/
void toggle_cursor(boolean show_cursor);

#endif 
