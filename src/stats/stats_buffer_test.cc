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

#include <string.h>
#include <unistd.h>

#include <cstdlib>
#include <thread>
// #include <stats_buffer.h>

#include "gtest/gtest.h"
#include <absl/synchronization/notification.h>

#include "../common.h"


void enqueue(struct StatsBuffer* statsbufff, void* ptr1, void* ptr2, int passive, int state) {
  statsbufff->enqueue(ptr1, ptr2, passive, state);
}

class StatsBufferTest : public ::testing::Test {
};

TEST_F(StatsBufferTest, TestMultipleEnqueue) {
  struct StatsBuffer statsbufff;
  StatsBufferInit(statsbufff);
  std::thread enqueue_thread1(enqueue, &statsbufff, (void*)(0x12345), nullptr, 1, 1);
  std::thread enqueue_thread2(enqueue, &statsbufff, (void*)(0x12346), nullptr, 1, 1);
  std::thread enqueue_thread3(enqueue, &statsbufff, (void*)(0x12347), nullptr, 1, 1);
  enqueue_thread1.detach();
  enqueue_thread2.detach();
  enqueue_thread3.detach();
  int cnt = 0;
  while (1) {
    pthread_mutex_lock(&statsbufff.mutex);
    while (statsbufff.empty() && statsbufff.alive()) {
      pthread_cond_wait(&statsbufff.notEmpty, &statsbufff.mutex);
    }
    pthread_mutex_unlock(&statsbufff.mutex);
    if (statsbufff.dequeue().c_str()) {
      cnt++;
    }
    if (cnt == 3) {
      break;
    }
  }
  ASSERT_EQ(cnt,3);
}

void dequeue(struct StatsBuffer* statsbufff, int* cnt, absl::Notification* notification) {
  while (1) {
    pthread_mutex_lock(&statsbufff->mutex);
    while (statsbufff->empty() && statsbufff->alive()) {
      pthread_cond_wait(&statsbufff->notEmpty, &statsbufff->mutex);
    }
    pthread_mutex_unlock(&statsbufff->mutex);
    if (statsbufff->dequeue().c_str()) {
      (*cnt)++;
    }
    if ((*cnt) == 3) {
      notification->Notify();
      break;
    }
  }
}

TEST_F(StatsBufferTest, TestCondVar) {
  struct StatsBuffer statsbufff;
  StatsBufferInit(statsbufff);
  absl::Notification notification;
  int cnt = 0;
  std::thread dequeue_thread1(dequeue, &statsbufff, &cnt, &notification);
  dequeue_thread1.detach();
  statsbufff.enqueue(nullptr, (void*)(0x12345), 1, 1);
  statsbufff.enqueue(nullptr, (void*)(0x12346), 1, 1);
  statsbufff.enqueue(nullptr, (void*)(0x12347), 1, 1);
  notification.WaitForNotificationWithTimeout(absl::Seconds(30));
  ASSERT_EQ(cnt, 3);
}