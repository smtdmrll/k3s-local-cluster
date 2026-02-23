@echo off
setlocal enabledelayedexpansion

set VM_NAME=k3s-cluster
set VM_RAM=4096
set VM_CPU=2
set VM_DISK=40000
set ISO_PATH=%USERPROFILE%\Downloads\ubuntu-24.04.1-live-server-amd64.iso
set VBOX_PATH=C:\Program Files\Oracle\VirtualBox

echo Creating VM: %VM_NAME%

"%VBOX_PATH%\VBoxManage.exe" createvm --name "%VM_NAME%" --ostype Ubuntu_64 --register

"%VBOX_PATH%\VBoxManage.exe" modifyvm "%VM_NAME%" --memory %VM_RAM% --cpus %VM_CPU% --vram 32
"%VBOX_PATH%\VBoxManage.exe" modifyvm "%VM_NAME%" --nic1 bridged --bridgeadapter1 "Intel(R) Wi-Fi 6 AX201 160MHz"
"%VBOX_PATH%\VBoxManage.exe" modifyvm "%VM_NAME%" --boot1 dvd --boot2 disk --boot3 none --boot4 none
"%VBOX_PATH%\VBoxManage.exe" modifyvm "%VM_NAME%" --graphicscontroller vmsvga
"%VBOX_PATH%\VBoxManage.exe" modifyvm "%VM_NAME%" --audio-enabled off

"%VBOX_PATH%\VBoxManage.exe" createhd --filename "%USERPROFILE%\VirtualBox VMs\%VM_NAME%\%VM_NAME%.vdi" --size %VM_DISK% --variant Standard

"%VBOX_PATH%\VBoxManage.exe" storagectl "%VM_NAME%" --name "SATA Controller" --add sata --controller IntelAhci
"%VBOX_PATH%\VBoxManage.exe" storageattach "%VM_NAME%" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "%USERPROFILE%\VirtualBox VMs\%VM_NAME%\%VM_NAME%.vdi"

"%VBOX_PATH%\VBoxManage.exe" storagectl "%VM_NAME%" --name "IDE Controller" --add ide
"%VBOX_PATH%\VBoxManage.exe" storageattach "%VM_NAME%" --storagectl "IDE Controller" --port 0 --device 0 --type dvddrive --medium "%ISO_PATH%"

echo VM created successfully
echo Starting VM...
"%VBOX_PATH%\VBoxManage.exe" startvm "%VM_NAME%"

echo.
echo After Ubuntu installation:
echo 1. Get VM IP: ip addr
echo 2. Copy project: scp -r k3s-local-cluster devops@VM_IP:~
echo 3. Run: sudo ./scripts/k3s-project.sh install
