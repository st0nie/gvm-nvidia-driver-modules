# Setup environment for GVM

Testes on `g2-standard-8` on GCP, with image `ubuntu-accelerator-2404-amd64-with-nvidia-580-v20251021` on `x86/64`.

## Setup

```bash
./download_pkgs.sh

# Required for images comes with NVIDIA driver
./uninstall_nv_driver.sh

./install_cuda.sh
# Select all default options
./install_nv_driver.sh
```

## Compile

```bash
./compile_modules.sh
```

## Cleanup

```bash
sudo reboot
```

## Install/uninstall kernel modules

```bash
./deploy_modules.sh  # if first time deploy kernel modules
./redeploy_uvm_module.sh  # uninstall previous kernel modules and re-deploy them
./uninstall_modules.sh  # uninstall previous kernel modules
```

## What to do when complaining about driver not loaded?

Sometimes you might see the following error:

```bash
$ nvidia-smi
NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver. Make sure that the latest NVIDIA driver is installed and running.
$ nvitop
NVML ERROR: Driver Not Loaded
```

This usually happens on restart of the VM. To fix this:

```bash
./deploy_modules.sh
```

