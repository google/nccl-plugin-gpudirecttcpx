# NCCL GPUDirectTCPX

NCCL GPUDirectTCPX is a transport layer plugin to improve NCCL collective
communication performance on Google Cloud.

## Overview

Collective communication primitives such as all-reduce and all-gather have been
widely used in distributed training in machine learning. The NVIDIA Collective
Communications Library (NCCL) is a highly optimized implementation of these
multi-GPU and multi-node collective communication primitives that supports
NVIDIA GPUs.

NCCL GPUDirectTCPX is based on TCP/IP communication and uses a number of
techniques to achieve better and more consistent performance, especially with
the A3 VM type 4-NIC networking on Google Cloud.

## Getting Started

### Dependencies

NCCL GPUDirectTCPX requires working installation of CUDA to build. After building the
plugin, it has to be in `LD_LIBRARY_PATH` in order to be loaded by NCCL.

### Build

The plugin uses CMake to build. You can build the plugin as follows:

```
$ cmake -S . -B build -DNCCL_INCLUDE_PATH=/repos/nccl/build/include
$ cmake --build build
```

The plugin is located at `build/libnccl-net.so` and can be copied into your
`LD_LIBRARY_PATH`.

## Getting Help

Please open an issue if you have any questions or if you think you may have
found any bugs.

## Contributing

Contributions are always welcomed. Please refer to our [contributing guidelines](CONTRIBUTING.md)
to learn how to contriute.

## License

NCCL GPUDirectTCPX is licensed under the terms of a BSD-style license.
See [LICENSE](LICENSE) for more information.