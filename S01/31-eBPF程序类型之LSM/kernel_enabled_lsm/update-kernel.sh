
echo GRUB_DISABLE_OS_PROBER=false | sudo tee -a /etc/default/grub
sudo dpkg -i *.deb
