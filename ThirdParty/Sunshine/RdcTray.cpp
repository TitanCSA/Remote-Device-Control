// The managed host's normal-user indicator owns all visible session UI.
#include <string>
#include "src/system_tray.h"
namespace system_tray {
void tray_open_ui_cb(tray_menu*){}
void tray_donate_github_cb(tray_menu*){}
void tray_donate_patreon_cb(tray_menu*){}
void tray_donate_paypal_cb(tray_menu*){}
void tray_reset_display_device_config_cb(tray_menu*){}
void tray_restart_cb(tray_menu*){}
void tray_quit_cb(tray_menu*){}
int init_tray(){return 0;}
int process_tray_events(){return 0;}
int end_tray(){return 0;}
int init_tray_threaded(){return 0;}
int end_tray_threaded(){return 0;}
void update_tray_playing(std::string){}
void update_tray_pausing(std::string){}
void update_tray_stopped(std::string){}
void update_tray_require_pin(){}
}
