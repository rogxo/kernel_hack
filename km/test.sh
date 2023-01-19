#clear
sudo dmesg --clear
rm -rf build
make clean && make
sudo insmod build/entry.ko
sudo rmmod entry
sudo dmesg
