#!/bin/bash
set -e

# enter kernel source code directory
cd /path/to/linux-6.13

# configure kernel (keep original config)
make oldconfig

# compile kernel
echo "Compiling kernel..."
make -j$(nproc)

# install kernel modules and image
sudo make modules_install
sudo make install

# reboot to new kernel
echo "Rebooting to the new kernel..."
sudo reboot