#ifndef PREFERRED_AP_HOST_IDF_H
#define PREFERRED_AP_HOST_IDF_H
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include <pthread.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"check %s:%d: %s\n",__FILE__,__LINE__,#x); abort(); } } while(0)
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_TIMEOUT 0x107
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_WIFI_NOT_CONNECT 0x300f
#define ESP_ERR_WIFI_STATE 0x3006
#define WIFI_IF_STA 0
#define WIFI_STORAGE_RAM 1
#define WIFI_ALL_CHANNEL_SCAN 1
#define WIFI_CONNECT_AP_BY_SIGNAL 0
#define WIFI_SCAN_TYPE_ACTIVE 0
#define HTTP_GET 0
#define HTTPD_500_INTERNAL_SERVER_ERROR 500
#define pdPASS 1
#define pdMS_TO_TICKS(x) (x)
typedef uint32_t EventBits_t;
typedef void *EventGroupHandle_t;
typedef pthread_mutex_t portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED PTHREAD_MUTEX_INITIALIZER
extern _Thread_local unsigned lock_depth;
#define portENTER_CRITICAL(p) do { CHECK(pthread_mutex_lock(p)==0); ++lock_depth; } while(0)
#define portEXIT_CRITICAL(p) do { --lock_depth; CHECK(pthread_mutex_unlock(p)==0); } while(0)
#define API() CHECK(lock_depth==0)
typedef int esp_event_base_t;
#define WIFI_EVENT 1
#define IP_EVENT 2
enum { WIFI_EVENT_STA_START=1, WIFI_EVENT_STA_STOP, WIFI_EVENT_SCAN_DONE,
       WIFI_EVENT_STA_DISCONNECTED, IP_EVENT_STA_GOT_IP, IP_EVENT_STA_LOST_IP };
typedef struct { uint32_t status; } wifi_event_sta_scan_done_t;
typedef struct { uint8_t bssid[6], reason; int8_t rssi; } wifi_event_sta_disconnected_t;
typedef struct {
    uint8_t ssid[32],password[64]; int scan_method; bool bssid_set; uint8_t bssid[6],channel;
    int sort_method; struct {int authmode; int8_t rssi;} threshold;
    /* Security fields must survive every preferred/fallback configuration. */
    struct {bool capable,required;} pmf_cfg;
    uint32_t sae_pwe_h2e, failure_retry_cnt, rm_enabled, btm_enabled;
    uint8_t future_security[16];
} wifi_sta_config_t;
typedef union { wifi_sta_config_t sta; } wifi_config_t;
typedef struct { uint8_t bssid[6], primary; int8_t rssi; int authmode; } wifi_ap_record_t;
typedef struct { uint8_t *ssid; int scan_type; struct {struct {uint32_t min,max;} active;} scan_time; } wifi_scan_config_t;
typedef struct { int unused; } esp_netif_t;
typedef struct {struct {uint32_t addr;} ip;} esp_netif_ip_info_t;
typedef struct {int unused;} httpd_req_t;
typedef void *httpd_handle_t;
typedef struct {const char *uri; int method; esp_err_t (*handler)(httpd_req_t *);} httpd_uri_t;
int64_t esp_timer_get_time(void);
esp_err_t esp_wifi_get_mac(int, uint8_t *);
esp_err_t esp_wifi_set_storage(int);
esp_err_t esp_wifi_set_config(int, wifi_config_t *);
esp_err_t esp_wifi_get_config(int, wifi_config_t *);
esp_err_t esp_wifi_start(void);
esp_err_t esp_wifi_connect(void);
esp_err_t esp_wifi_disconnect(void);
esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t *);
esp_err_t esp_wifi_scan_start(const wifi_scan_config_t *,bool);
esp_err_t esp_wifi_scan_stop(void);
esp_err_t esp_wifi_clear_ap_list(void);
esp_err_t esp_wifi_scan_get_ap_num(uint16_t *);
esp_err_t esp_wifi_scan_get_ap_records(uint16_t *,wifi_ap_record_t *);
esp_netif_t *esp_netif_get_handle_from_ifkey(const char *);
bool esp_netif_is_netif_up(esp_netif_t *);
esp_err_t esp_netif_get_ip_info(esp_netif_t *,esp_netif_ip_info_t *);
int xTaskCreate(void (*)(void*),const char *,unsigned,void*,unsigned,void*);
void vTaskDelay(unsigned);
EventBits_t xEventGroupSetBits(EventGroupHandle_t,EventBits_t);
EventBits_t xEventGroupClearBits(EventGroupHandle_t,EventBits_t);
esp_err_t httpd_register_uri_handler(httpd_handle_t,const httpd_uri_t *);
esp_err_t httpd_resp_send_err(httpd_req_t *,int,const char *);
esp_err_t httpd_resp_set_type(httpd_req_t *,const char *);
esp_err_t httpd_resp_send(httpd_req_t *,const char *,ssize_t);

#endif
