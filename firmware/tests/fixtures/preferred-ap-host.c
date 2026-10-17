#include "preferred-ap-idf.h"
#include "home_wifi_policy.c"
#include <limits.h>
_Thread_local unsigned lock_depth;
static uint64_t now_ms;
static wifi_config_t driver_config, original;
static bool associated, ip_up, disconnect_stuck;
static uint8_t hardware_mac[6]={0x02,0,0,0,0,2};
static int fail_mac,fail_storage,fail_create,fail_config,fail_connect,fail_start;
static int fail_scan,fail_count,fail_records,fail_stop,fail_clear,fail_ap,fail_get_config;
static unsigned creates,starts,connects,disconnects,scan_starts,clears,config_sets;
static uint16_t scan_total=20;
static unsigned ready_bits;
static esp_netif_t netif;
static httpd_uri_t registered;
static char response[4096]; static size_t response_length;
static unsigned http_errors;

int64_t esp_timer_get_time(void){return (int64_t)now_ms*1000;}
esp_err_t esp_wifi_get_mac(int i,uint8_t *p){API();CHECK(i==WIFI_IF_STA);memcpy(p,hardware_mac,6);return fail_mac;}
esp_err_t esp_wifi_set_storage(int x){API();CHECK(x==WIFI_STORAGE_RAM);return fail_storage;}
esp_err_t esp_wifi_set_config(int i,wifi_config_t *c){
    API();CHECK(i==WIFI_IF_STA);++config_sets;
    wifi_config_t normalized=*c;
    normalized.sta.bssid_set=original.sta.bssid_set;
    memcpy(normalized.sta.bssid,original.sta.bssid,6);
    normalized.sta.channel=original.sta.channel;
    normalized.sta.scan_method=original.sta.scan_method;
    normalized.sta.sort_method=original.sta.sort_method;
    CHECK(memcmp(&normalized,&original,sizeof(original))==0);
    if (fail_config)
        return fail_config;
    driver_config=*c;return ESP_OK;
}
esp_err_t esp_wifi_get_config(int i,wifi_config_t *c){API();CHECK(i==WIFI_IF_STA);*c=driver_config;return fail_get_config;}
esp_err_t esp_wifi_start(void){API();++starts;return fail_start;}
esp_err_t esp_wifi_connect(void){API();++connects;return fail_connect;}
esp_err_t esp_wifi_disconnect(void){
    API();
    ++disconnects;
    if (!disconnect_stuck) {
        associated=false;
        ip_up=false;
    }
    return associated?ESP_OK:ESP_ERR_WIFI_NOT_CONNECT;
}
esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t *a){
    API();
    memset(a,0xa5,sizeof(*a));
    if (fail_ap)
        return fail_ap;
    if (!associated)
        return ESP_ERR_WIFI_NOT_CONNECT;
    const uint8_t fallback[6]={0x02,0,0,0,1,3};
    memcpy(a->bssid,driver_config.sta.bssid_set?driver_config.sta.bssid:fallback,6);
    a->primary=driver_config.sta.bssid_set?11:1;a->rssi=-50;a->authmode=3;return ESP_OK;
}
esp_err_t esp_wifi_scan_start(const wifi_scan_config_t *c,bool block){
    API();++scan_starts;CHECK(!block);CHECK(c->ssid!=NULL);
    CHECK(strcmp((char*)c->ssid,"home-test")==0);CHECK(c->scan_type==WIFI_SCAN_TYPE_ACTIVE);
    CHECK(c->scan_time.active.max==120);return fail_scan;
}
esp_err_t esp_wifi_scan_stop(void){API();return fail_stop;}
esp_err_t esp_wifi_clear_ap_list(void){API();++clears;return fail_clear;}
esp_err_t esp_wifi_scan_get_ap_num(uint16_t *n){API();*n=scan_total;return fail_count;}
esp_err_t esp_wifi_scan_get_ap_records(uint16_t *n,wifi_ap_record_t *a){
    API();
    CHECK(*n==HWP_SCAN_MAX);
    if (fail_records)
        return fail_records;
    if (*n>scan_total)
        *n=scan_total;
    for(unsigned i=0;i<*n;++i){memset(&a[i],0,sizeof(a[i]));a[i].bssid[0]=2;a[i].bssid[5]=(uint8_t)i;a[i].primary=11;a[i].rssi=-40;a[i].authmode=3;}
    return ESP_OK;
}
esp_netif_t *esp_netif_get_handle_from_ifkey(const char *k){API();CHECK(strcmp(k,"WIFI_STA_DEF")==0);return &netif;}
bool esp_netif_is_netif_up(esp_netif_t *n){API();CHECK(n==&netif);return ip_up;}
esp_err_t esp_netif_get_ip_info(esp_netif_t *n,esp_netif_ip_info_t *i){API();CHECK(n==&netif);i->ip.addr=ip_up?1:0;return ESP_OK;}
int xTaskCreate(void(*f)(void*),const char*n,unsigned stack,void*arg,unsigned priority,void*out){
    API();CHECK(f!=NULL&&strcmp(n,"home_wifi")==0&&stack>=6144&&arg==NULL&&priority==4&&out==NULL);++creates;return fail_create?0:pdPASS;
}
void vTaskDelay(unsigned ticks){(void)ticks;abort();}
EventBits_t xEventGroupSetBits(EventGroupHandle_t g,EventBits_t b){API();CHECK(g==(void*)1);ready_bits|=b;return ready_bits;}
EventBits_t xEventGroupClearBits(EventGroupHandle_t g,EventBits_t b){API();CHECK(g==(void*)1);ready_bits&=~b;return ready_bits;}
esp_err_t httpd_register_uri_handler(httpd_handle_t s,const httpd_uri_t *u){API();CHECK(s==(void*)1);registered=*u;return ESP_OK;}
esp_err_t httpd_resp_send_err(httpd_req_t *r,int code,const char*m){API();(void)r;(void)m;CHECK(code==500);++http_errors;return ESP_FAIL;}
esp_err_t httpd_resp_set_type(httpd_req_t*r,const char*t){API();(void)r;CHECK(strcmp(t,"application/json")==0);return ESP_OK;}
esp_err_t httpd_resp_send(httpd_req_t*r,const char*b,ssize_t n){API();(void)r;CHECK(n>0&&(size_t)n<sizeof(response));CHECK(strlen(b)==(size_t)n);memcpy(response,b,(size_t)n+1);response_length=(size_t)n;return ESP_OK;}

#if EXPECT_ACTIVE
static void reset(void){
    memset(&s_events,0,sizeof(s_events));memset(&s_status,0,sizeof(s_status));
    s_status.gate="not_initialized";s_status.phase="disabled";s_status.error_operation="none";
    s_active=s_targeted=false;memset(&s_core,0,sizeof(s_core));
    s_scan_started=s_scan_finished=s_pending=s_boot_issued=false;
    s_boot_backoff=0;s_boot_at=s_boot_deadline=s_seen_stop=0;
    s_scan_deadline=s_barrier_deadline=s_quiet_until=s_barrier_sequence=0;
    now_ms=0;associated=ip_up=disconnect_stuck=false;
    fail_mac=fail_storage=fail_create=fail_config=fail_connect=fail_start=0;
    fail_scan=fail_count=fail_records=fail_stop=fail_clear=fail_ap=fail_get_config=0;
    creates=starts=connects=disconnects=scan_starts=clears=config_sets=ready_bits=0;
    scan_total=20;http_errors=0;memset(&registered,0,sizeof(registered));
    hardware_mac[5]=2;
    memset(&original,0,sizeof(original));strcpy((char*)original.sta.ssid,"home-test");
    strcpy((char*)original.sta.password,"do-not-serialize-this");original.sta.threshold.authmode=3;
    original.sta.threshold.rssi=-100;original.sta.pmf_cfg.capable=true;original.sta.pmf_cfg.required=true;
    original.sta.sae_pwe_h2e=2;memset(original.sta.future_security,0xd3,sizeof(original.sta.future_security));
    driver_config=original;
}
static void at(uint64_t when){now_ms=when;tick(when);}
static void event(int base,int id){CHECK(home_wifi_policy_event(base,id,NULL));}
static void dis(uint8_t reason){wifi_event_sta_disconnected_t d={{0x02,0,0,0,1,2},reason,-70};CHECK(home_wifi_policy_event(WIFI_EVENT,WIFI_EVENT_STA_DISCONNECTED,&d));}
static void init(void){CHECK(home_wifi_policy_init(&original,2,(void*)1,1));}
static void boot(void){init();at(0);CHECK(starts==1&&connects==0);event(WIFI_EVENT,WIFI_EVENT_STA_START);at(100);CHECK(scan_starts==1);wifi_event_sta_scan_done_t done={0};CHECK(home_wifi_policy_event(WIFI_EVENT,WIFI_EVENT_SCAN_DONE,&done));at(200);at(400);CHECK(connects==1&&driver_config.sta.bssid_set);}
static void test_gate_and_setup(void){
    uint8_t mac[6];CHECK(hwp_parse_mac("02:00:00:00:01:02",mac));
    const char *bad[]={"", "00:00:00:00:00:00","ff:ff:ff:ff:ff:ff","03:00:00:00:01:02","02:00:00:00:01:02x","02-00:00:00:01:02","02:00:00:00:01:0z"};
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);++i)CHECK(!hwp_parse_mac(bad[i],mac));
    reset();CHECK(!home_wifi_policy_init(&original,1,(void*)1,1));CHECK(creates==0&&!home_wifi_policy_targeted()&&strcmp(s_status.gate,"node_mismatch")==0);
    reset();hardware_mac[5]=3;CHECK(!home_wifi_policy_init(&original,2,(void*)1,1));CHECK(creates==0&&strcmp(s_status.gate,"mac_mismatch")==0);
    reset();fail_mac=12;CHECK(!home_wifi_policy_init(&original,2,(void*)1,1));CHECK(s_status.last_error==12);
    reset();fail_storage=13;CHECK(!home_wifi_policy_init(&original,2,(void*)1,1));CHECK(creates==0);
    reset();fail_create=1;CHECK(!home_wifi_policy_init(&original,2,(void*)1,1));CHECK(!s_active&&home_wifi_policy_targeted()&&strcmp(s_status.gate,"worker_failed")==0);
    CHECK(!home_wifi_policy_event(WIFI_EVENT,WIFI_EVENT_STA_START,NULL));
    CHECK(home_wifi_policy_register_http((void*)1)==ESP_OK);CHECK(strcmp(registered.uri,"/wifi/status")==0);
    CHECK(registered.handler(NULL)==ESP_OK);CHECK(strstr(response,"worker_failed")!=NULL);
}
static void test_scan(void){
    reset();boot();CHECK(clears==1&&s_status.scan_count==16&&s_status.scan_total==20&&s_status.scan_truncated);
    for(unsigned i=0;i<4;++i){
        reset();init();at(0);event(WIFI_EVENT,WIFI_EVENT_STA_START);
        if (i==0)
            fail_scan=11;
        if (i==1)
            fail_count=12;
        if (i==2)
            fail_records=13;
        if (i==3) {
            fail_stop=14;
            fail_clear=15;
        }
        at(100);
        if (i!=0&&i!=3) {
            wifi_event_sta_scan_done_t done={0};
            CHECK(home_wifi_policy_event(WIFI_EVENT,WIFI_EVENT_SCAN_DONE,&done));
        }
        at(i==3?6100:200);at(i==3?6300:400);
        CHECK(clears==1&&s_status.scan_finished);CHECK(connects==1);CHECK(s_status.scan_error!=0);
    }
}
static void test_no_ap_and_auth_reject(void){
    reset();boot();
    dis(201);at(500);CHECK(s_core.failures==0); /* Unassociated late events cannot identify an attempt. */
    event(IP_EVENT,IP_EVENT_STA_GOT_IP);at(1000);CHECK(ready_bits==0&&s_core.phase!=HWP_ONLINE);
    dis(202);at(2000);CHECK(s_core.failures==0);
    at(30200);CHECK(s_core.phase==HWP_FALLBACK_WAIT&&!s_core.preferred);
    CHECK(s_core.next_at==35200);at(35199);CHECK(connects==1);
    at(35200);dis(8);at(35300);at(35500);CHECK(connects==2&&!driver_config.sta.bssid_set);
    dis(202);event(IP_EVENT,IP_EVENT_STA_GOT_IP);at(35600);CHECK(s_core.failures==1&&ready_bits==0);
    at(65200);CHECK(s_core.phase==HWP_FALLBACK_WAIT&&s_core.next_at==75200);
    at(75200);at(75400);CHECK(connects==3);
    at(105200);CHECK(s_core.next_at==125200);
    at(125200);at(125400);at(155200);CHECK(s_core.next_at==195200);
    at(195200);at(195400);at(225200);CHECK(s_core.next_at==285200);
}
static void test_sync_failures_and_start(void){
    reset();fail_config=19;init();at(0);CHECK(starts==0&&s_status.last_error==19);fail_config=0;at(4999);CHECK(starts==0);at(5000);CHECK(starts==1);
    reset();fail_start=20;init();at(0);CHECK(starts==1);at(5000);CHECK(starts==2);fail_start=0;at(15000);CHECK(starts==3);event(WIFI_EVENT,WIFI_EVENT_STA_START);at(15100);CHECK(scan_starts==1);
    reset();boot();fail_connect=21;
    /* Real association observed, then lost: safe early failure, unlike stale callbacks. */
    associated=true;at(500);associated=false;dis(4);at(600);CHECK(s_core.failures==1);
    at(1600);at(1800);CHECK(s_core.failures==2);at(2800);at(3000);CHECK(s_core.failures==3&&!s_core.preferred);
    CHECK(s_status.last_error==21);
    reset();boot();associated=true;at(500);associated=false;at(600);fail_config=22;at(1600);at(1800);CHECK(s_status.last_error==22&&s_core.failures==2);
}
static void test_dhcp_and_barrier(void){
    reset();boot();associated=true;at(500);CHECK(ready_bits==0);at(30199);CHECK(s_core.preferred);at(30200);CHECK(!s_core.preferred&&!associated);
    reset();boot();associated=true;at(500);disconnect_stuck=true;at(30200);CHECK(associated);
    at(35200);at(36700);CHECK(s_status.last_error==ESP_ERR_TIMEOUT&&strcmp(s_status.error_operation,"disconnect_barrier")==0);CHECK(connects==1);
}
static void test_healthy_fallback_and_races(void){
    reset();boot();at(30200);at(35200);at(35400);associated=ip_up=true;event(IP_EVENT,IP_EVENT_STA_GOT_IP);dis(8);at(35500);
    CHECK(ready_bits==1&&s_core.phase==HWP_ONLINE&&!s_core.preferred);
    unsigned n=connects,d=disconnects;
    fail_ap=ESP_FAIL;at(36000);CHECK(s_core.phase==HWP_ONLINE&&connects==n&&disconnects==d);fail_ap=0;
    for(uint64_t t=40000;t<900000;t+=1000)at(t);
    CHECK(connects==n&&disconnects==d&&scan_starts==1);
    /* Lost IP, without a Wi-Fi disconnect, has an independent30s deadline. */
    ip_up=false;event(IP_EVENT,IP_EVENT_STA_LOST_IP);at(900000);CHECK(ready_bits==0);at(930000);CHECK(s_core.phase==HWP_FALLBACK_WAIT);
    /* START/STOP events cannot overflow; STOP disallows connect until restarted. */
    event(WIFI_EVENT,WIFI_EVENT_STA_STOP);at(930100);CHECK(s_core.phase==HWP_STOPPED);
    at(935100);CHECK(starts==2);event(WIFI_EVENT,WIFI_EVENT_STA_START);at(935200);CHECK(scan_starts==1);
    reset();init();event(WIFI_EVENT,WIFI_EVENT_STA_START);at(1);CHECK(scan_starts==1&&starts==0); /* START before first worker turn. */
}
static void test_natural_disconnect_cooldown(void){
    reset();boot();associated=ip_up=true;at(500);CHECK(ready_bits==1);
    associated=ip_up=false;dis(4);at(1000);CHECK(!s_core.preferred&&s_core.next_at==6000);
    at(6000);at(6200);associated=ip_up=true;at(6300);
    associated=ip_up=false;dis(4);at(301000);CHECK(s_core.preferred&&s_core.phase==HWP_PREFERRED_CONNECTING);
}
static void *flood(void *unused){(void)unused;for(unsigned i=0;i<10000;++i){event(IP_EVENT,IP_EVENT_STA_GOT_IP);dis(4);}return NULL;}
static void test_mailbox_and_json(void){
    reset();boot();pthread_t thread;CHECK(pthread_create(&thread,NULL,flood,NULL)==0);
    for(unsigned i=0;i<10000;++i){mailbox_t m=mailbox();CHECK(m.got_ip_count>=m.disconnect_count);}
    CHECK(pthread_join(thread,NULL)==0);CHECK(s_events.got_ip_count==10000&&s_events.disconnect_count==10000);
    s_events.got_ip_count=UINT32_MAX;s_events.disconnect_count=UINT32_MAX;event(IP_EVENT,IP_EVENT_STA_GOT_IP);dis(4);
    CHECK(s_events.got_ip_count==UINT32_MAX&&s_events.disconnect_count==UINT32_MAX);
    at(500);CHECK(home_wifi_policy_register_http((void*)1)==ESP_OK);CHECK(registered.handler(NULL)==ESP_OK);
    CHECK(strstr(response,"do-not-serialize-this")==NULL&&strstr(response,"home-test")==NULL);
    puts(response);
    status_t max=s_status;max.gate="invalid_configuration";max.phase="preferred_connecting";max.error_operation="start_event_timeout";max.associated=max.ip_ready=max.effective_valid=true;
    max.attempts=max.failures=max.fallback_entries=UINT32_MAX;max.next_attempt_ms=max.preferred_deadline_ms=UINT64_MAX;
    max.last_error=max.ap_error=max.config_error=max.scan_error=INT_MIN;max.scan_method=max.sort_method=INT_MIN;
    /* Numeric stress-test fields, never authentication secrets. */
    max.auth_threshold=INT_MIN;max.rssi_threshold=INT_MIN;
    max.channel_hint=255;memset(&max.current,0xff,sizeof(max.current));max.current.authmode=INT_MIN;max.current.rssi=INT8_MIN;
    max.scan_count=16;max.scan_total=UINT16_MAX;max.scan_truncated=true;
    max.events.last_disconnect_ms=UINT64_MAX;max.events.disconnect_count=max.events.got_ip_count=max.events.lost_ip_count=UINT32_MAX;
    max.events.reason=255;max.events.rssi=INT8_MIN;
    for(unsigned i=0;i<16;++i)max.scan[i]=max.current;
    char text[4096];size_t used;CHECK(render(&max,text,sizeof(text),&used));CHECK(used<sizeof(text));puts(text);
    char small[8];CHECK(!render(&max,small,sizeof(small),&used));
    fail_get_config=26;fail_ap=27;at(600);CHECK(registered.handler(NULL)==ESP_OK);puts(response);
}
int main(void){
    test_gate_and_setup();test_scan();test_no_ap_and_auth_reject();test_sync_failures_and_start();
    test_dhcp_and_barrier();test_healthy_fallback_and_races();test_natural_disconnect_cooldown();test_mailbox_and_json();
    return 0;
}
#else
int main(void){
    CHECK(!home_wifi_policy_init(&original,2,(void*)1,1));CHECK(creates==0);
    CHECK(!home_wifi_policy_event(WIFI_EVENT,WIFI_EVENT_STA_START,NULL));
    CHECK(home_wifi_policy_register_http((void*)1)==ESP_OK);
    return 0;
}
#endif
