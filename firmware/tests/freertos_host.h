/* POSIX model of the FreeRTOS primitives used by the WASM worker test.
 * Host stacks are deliberately left at the pthread default for ASAN. This
 * checks execution context, ownership and completion, not ESP32 stack margin. */
#pragma once
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define pdTRUE 1
#define pdPASS 1
#define portMAX_DELAY (-1)

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    unsigned count;
} *SemaphoreHandle_t;
static inline SemaphoreHandle_t test_sem(unsigned count) {
    SemaphoreHandle_t s = calloc(1, sizeof(*s)); assert(s);
    pthread_mutex_init(&s->lock, NULL); pthread_cond_init(&s->changed, NULL);
    s->count = count; return s;
}
static inline SemaphoreHandle_t xSemaphoreCreateMutex(void) { return test_sem(1); }
static inline SemaphoreHandle_t xSemaphoreCreateBinary(void) { return test_sem(0); }
static inline int xSemaphoreTake(SemaphoreHandle_t s, int wait) {
    pthread_mutex_lock(&s->lock);
    while (!s->count && wait) pthread_cond_wait(&s->changed, &s->lock);
    int ok = s->count != 0;
    if (ok) s->count--;
    pthread_mutex_unlock(&s->lock); return ok;
}
static inline void xSemaphoreGive(SemaphoreHandle_t s) {
    pthread_mutex_lock(&s->lock); assert(s->count == 0); s->count = 1;
    pthread_cond_signal(&s->changed); pthread_mutex_unlock(&s->lock);
}
static inline void vSemaphoreDelete(SemaphoreHandle_t s) {
    pthread_mutex_destroy(&s->lock); pthread_cond_destroy(&s->changed); free(s);
}

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    void *item;
    int present;
} *QueueHandle_t;
static inline QueueHandle_t xQueueCreate(unsigned length, unsigned item_size) {
    assert(length == 1 && item_size == sizeof(void *));
    QueueHandle_t q = calloc(1, sizeof(*q)); assert(q);
    pthread_mutex_init(&q->lock, NULL); pthread_cond_init(&q->changed, NULL);
    return q;
}
static inline int xQueueSend(QueueHandle_t q, const void *item, int wait) {
    pthread_mutex_lock(&q->lock);
    while (q->present && wait) pthread_cond_wait(&q->changed, &q->lock);
    int ok = !q->present;
    if (ok) { q->item = *(void *const *)item; q->present = 1; pthread_cond_broadcast(&q->changed); }
    pthread_mutex_unlock(&q->lock); return ok;
}
static inline int xQueueReceive(QueueHandle_t q, void *out, int wait) {
    pthread_mutex_lock(&q->lock);
    while (!q->present && wait) pthread_cond_wait(&q->changed, &q->lock);
    int ok = q->present;
    if (ok) { *(void **)out = q->item; q->present = 0; pthread_cond_broadcast(&q->changed); }
    pthread_mutex_unlock(&q->lock); return ok;
}
static inline void vQueueDelete(QueueHandle_t q) {
    pthread_mutex_destroy(&q->lock); pthread_cond_destroy(&q->changed); free(q);
}

/* FreeRTOS task handles are nullable opaque pointers, not pthread identifiers.
 * This model has one worker; retain its native identity separately so NULL
 * means "the current task" on both integer-pthread and pointer-pthread hosts. */
typedef pthread_t *TaskHandle_t;
extern pthread_t test_worker_thread;
extern atomic_int test_task_creations, test_self_deletes;
extern int test_fail_task_create;
typedef struct { void (*entry)(void *); void *arg; } test_task_start_t;
static inline void *test_task_start(void *arg) {
    test_task_start_t start = *(test_task_start_t *)arg; free(arg);
    test_worker_thread = pthread_self(); start.entry(start.arg); return NULL;
}
static inline int xTaskCreatePinnedToCore(void (*entry)(void *), const char *name,
                                        unsigned bytes, void *arg, unsigned priority,
                                        TaskHandle_t *task, int core) {
    assert(bytes == 32768 && priority == 5 && core == 1);
    assert(strcmp(name, "wasm_worker") == 0);
    test_task_start_t *start = malloc(sizeof(*start)); assert(start);
    *start = (test_task_start_t){entry, arg};
    pthread_t native_thread;
    *task = &test_worker_thread;
    int result = test_fail_task_create ? 1 :
        pthread_create(&native_thread, NULL, test_task_start, start);
    if (result != 0) {
        *task = NULL;
        free(start);
        return 0;
    }
    test_task_creations++;
    return pdPASS;
}
static inline void vTaskDelete(TaskHandle_t task) {
    assert(!task); /* Production initialization failure must self-delete. */
    pthread_detach(pthread_self()); test_self_deletes++; pthread_exit(NULL);
}
static inline unsigned uxTaskGetStackHighWaterMark(TaskHandle_t task) {
    (void)task; return 12345; /* Fixture value, never an actual host watermark. */
}
