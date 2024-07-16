/*
 Copyright 2024 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

#ifndef NET_GPUDIRECTTCPX_STATS_STATS_BUFFER_H_
#define NET_GPUDIRECTTCPX_STATS_STATS_BUFFER_H_

#include "../macro.h"
#include "../work_queue.h"
#include "../common.h"

constexpr int MAX_ITEMS = 10000;  // Maximum number of items
constexpr int NSTATES = 2;            // Two states: enqueue and dequeue

enum tcpxExporterState {
  EXPORTER_ENQUEUE = 0,
  EXPORTER_DEQUEUE = 1,
  EXPORTER_MAX_STATES = 2,
};

struct StatsBuffer {
#ifdef TCPX_TRACEPOINT
  tcpxItemQueue<std::atomic_uint32_t, std::uint32_t, char*, MAX_ITEMS,
                EXPORTER_MAX_STATES>
      queue;

  // Constructor initializes the queue
  StatsBuffer() : queue() {}

  // Enqueue a string
  void enqueue(void* request, void* task, bool passive, int state) {
    // best effort when enqueue in main thread
    pthread_mutex_lock(&mutex);
    if (!queue.has_free()) {
      pthread_mutex_unlock(&mutex);
      return;
    }
    if (request != nullptr) {
      if ((long)request % kSamplingFactor == 0) {
        snprintf(*queue.first<EXPORTER_ENQUEUE>(), kLogLineLimit,
                 "R %p %d %d %ld", request, passive, state,
                 std::chrono::high_resolution_clock::now()
                     .time_since_epoch()
                     .count());
        queue.enqueue_internal();
        pthread_cond_signal(&notEmpty);
      }
    } else if (task != nullptr) {
      if ((long)task % kSamplingFactor == 0) {
        snprintf(*queue.first<EXPORTER_ENQUEUE>(), kLogLineLimit,
                 "T %p %d %d %ld", task, passive, state,
                 std::chrono::high_resolution_clock::now()
                     .time_since_epoch()
                     .count());
        queue.enqueue_internal();
        pthread_cond_signal(&notEmpty);
      }
    }
    pthread_mutex_unlock(&mutex);
  }

  // Dequeue a string and wait for signal
  std::string dequeue() {
    pthread_mutex_lock(&mutex);
    while (!queue.has<EXPORTER_DEQUEUE>()) {
      pthread_cond_wait(&notEmpty, &mutex);
    }
    std::string data = dequeue_one_element();
    if (empty()) {
      pthread_cond_signal(&isEmpty);
    }
    pthread_mutex_unlock(&mutex);
    return data;
  }

  std::string dequeue_one_element() {
    char data[kLogLineLimit];
    strcpy(data, *queue.first<EXPORTER_DEQUEUE>());
    queue.dequeue_internal();
    return data;
  }

  bool empty() { return queue.empty(); }
  bool alive() { return alive_; }

  pthread_mutex_t mutex;
  pthread_cond_t notEmpty;
  pthread_cond_t isEmpty;
  bool alive_;
#endif
};

void inline StatsBufferInit(struct StatsBuffer& sb) {
#ifdef TCPX_TRACEPOINT
  pthread_mutex_init(&sb.mutex, NULL);
  pthread_cond_init(&sb.notEmpty, NULL);
  pthread_cond_init(&sb.isEmpty, NULL);
  *sb.queue.items = (char*)malloc(kLogLineLimit*MAX_ITEMS);
  for (int i=0;i<MAX_ITEMS; i++) {
    *(sb.queue.items + i) = *sb.queue.items + i*kLogLineLimit;
  }
  sb.alive_ = 1;
#endif
}

void inline StatsBufferDestructQueue(struct StatsBuffer& sb){
#ifdef TCPX_TRACEPOINT
  pthread_mutex_lock(&sb.mutex);
  while(!sb.empty()){
    pthread_cond_wait(&sb.isEmpty, &sb.mutex);
  }
  sb.alive_ = 0;
  free(*sb.queue.items);
  pthread_cond_signal(&sb.notEmpty);
  pthread_mutex_unlock(&sb.mutex);
#endif
}

void inline StatsBufferDestruct(struct StatsBuffer& sb) {
#ifdef TCPX_TRACEPOINT
  pthread_cond_destroy(&sb.notEmpty);
  pthread_cond_destroy(&sb.isEmpty);
  pthread_mutex_destroy(&sb.mutex);
#endif
}

#endif  // NET_GPUDIRECTTCPX_STATS_STATS_BUFFER_H_