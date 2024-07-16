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

#ifndef NET_GPUDIRECTTCPX_STATS_EXPORTER_H_
#define NET_GPUDIRECTTCPX_STATS_EXPORTER_H_

#include "monitoring.h"

#include <chrono>
#include <fstream>
#include <iostream>

#include "../macro.h"
#include "../work_queue_states.h"

namespace net_gpudirecttcpx_stats {

class Exporter {
 public:
   Exporter(const std::string &filename, tcpxComm* comm)
       : comm_(comm) {
     ofs_.open(filename, std::ios_base::app);
   }

   void appendToFile() {
#ifdef TCPX_TRACEPOINT
     while (true) {
       pthread_mutex_lock(&comm_->statsbuf.mutex);
       while (comm_->statsbuf.empty() && comm_->statsbuf.alive()) {
         // This timestamp is being added just as a separator in the log file.
         // This roughly indicates the events that occured between 2 timstamps in the log file.
         auto time_now = std::chrono::system_clock::to_time_t(
             std::chrono::system_clock::now());
         ofs_ << std::ctime(&time_now) << std::endl;
         pthread_cond_wait(&comm_->statsbuf.notEmpty, &comm_->statsbuf.mutex);
       }
       pthread_mutex_unlock(&comm_->statsbuf.mutex);
       if (!comm_->statsbuf.alive()) return;
       std::string data = comm_->statsbuf.dequeue();
       ofs_ << data << std::endl;
     }
#endif
     ofs_ << std::endl;
   };
   std::ofstream ofs_;
   tcpxComm* comm_ = nullptr;
};


class Exporter_stats {
  public:
   Exporter_stats(const std::string &filename, tcpxComm* comm)
       : comm_(comm) {

     ofs_.open(filename, std::ios_base::app);
   }
   void appendToFile() {
     auto time_now = std::chrono::system_clock::to_time_t(
                 std::chrono::system_clock::now());
     ofs_ << std::ctime(&time_now) << std::endl;
     for (int i = 0; i < comm_->num_socks; i++) {
       char logStr[kLogLineLimit];
       snprintf(logStr, kLogLineLimit, "per_flow_stats[%ld:%s] = %s",
               generateFlowId(comm_->fd_data[i].flow_str),
               comm_->fd_data[i].flow_str,
               tcpxSocketStatsToString(comm_->fd_data[i].stats, comm_->passive)
                   .c_str());
       ofs_ << logStr << std::endl;
     }
     time_now =
         std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
     ofs_ << std::ctime(&time_now) << std::endl;
   }
   std::ofstream ofs_;
   tcpxComm* comm_ = nullptr;
};
};
#endif  // NET_GPUDIRECTTCPX_STATS_EXPORTER_H_