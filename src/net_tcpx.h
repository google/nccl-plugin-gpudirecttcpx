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

#ifndef NET_GPUDIRRECTTCPX_NET_TCPX_H_
#define NET_GPUDIRRECTTCPX_NET_TCPX_H_

#include "adapter1.h"

tcpxResult_t tcpxInit(tcpxDebugLogger_t logFunction);

tcpxResult_t tcpxGetProperties(int dev, tcpxNetProperties_t *props);

tcpxResult_t tcpxDevices(int *ndev);

tcpxResult_t tcpxListen(int dev, void *oHandle, void **listenComm);

tcpxResult_t tcpxConnect_v5(int dev, void *oHandle, void **sendComm,
                                    devNetDeviceHandle** sendDevHandle);

tcpxResult_t tcpxAccept_v5(void* listenComm, void** recvComm, 
                                    devNetDeviceHandle** recvDevHandle);

tcpxResult_t tcpxRegMr(void *ocomm, void *data, int size, int type,
                                    void **mhandle);

tcpxResult_t tcpxDeregMr(void *ocomm, void *mhandle);

tcpxResult_t tcpxIsend_v5(void *sendComm, void *data, int size,
                                       int tag, void *mhandle, void **request);

tcpxResult_t tcpxIrecv_v5(void *recvComm, int n, void **data,
                                       int *sizes, int *tags, void **mhandles,
                                       void **request);

tcpxResult_t tcpxIflush_v5(void *recvComm, int n, void **data,
                                        int *sizes, void **mhandle,
                                        void **request);

tcpxResult_t tcpxTest(void *request, int *done, int *size);

tcpxResult_t tcpxClose(void *oComm);

tcpxResult_t tcpxCloseListen(void *oComm);

tcpxResult_t tcpxGetDeviceHandle(void *ocomm, int tag,
                                              devNetDeviceHandle *handle);
tcpxResult_t tcpxGetDeviceMr(void *comm, void *mhandle,
                                          void **dptr_mhandle);
tcpxResult_t tcpxIrecvConsumed(void *ocomm, int n, void *request);

#endif // NET_GPUDIRRECTTCPX_NET_TCPX_H_
