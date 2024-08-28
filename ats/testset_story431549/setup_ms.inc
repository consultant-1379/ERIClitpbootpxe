# Users credentials
litpcrypt set key-for-root root '12shroot'

# Create OS Profile
litp create -t os-profile -p /software/profiles/rhel_6_10 -o name=sample-profile version=rhel6 path=/var/www/html/6.10/os/x86_64/ arch=x86_64 breed=redhat kopts_post='console=tty50,115200'

# Create Management Server
litp create -t system -p /infrastructure/systems/system_ms -o system_name=ms1

# Create management and traffic networks
litp create -t network -p /infrastructure/networking/networks/mgmt -o name=mgmt litp_management=true subnet=192.168.56.0/24
litp create -t route -p /infrastructure/networking/routes/default -o subnet=0.0.0.0/0 gateway=192.168.56.1

# Cobbler setup for management server
litp inherit -p /ms/system -s /infrastructure/systems/system_ms
#litp create -t cobbler-service -p /ms/services/cobbler
litp create -t eth -p /ms/network_interfaces/if0 -o network_name=mgmt ipaddress=192.168.56.107 macaddress=08:00:27:FD:D6:34 device_name=eth0
litp inherit -p /ms/routes/default -s /infrastructure/networking/routes/default

# Create a two node system
litp create -t blade -p /infrastructure/systems/system_1 -o system_name=testNodeVM
litp create -t bmc -p /infrastructure/systems/system_1/bmc -o ipaddress=192.168.56.108 username=root password_key=key-for-root
litp create -t disk -p /infrastructure/systems/system_1/disks/disk0 -o name=hd0 size=50G bootable=true uuid="ATA_VBOX_HARDDISK_VB95c74353-6f9f6148"

litp create -t blade -p /infrastructure/systems/system_2 -o system_name=MN2VM
litp create -t bmc -p /infrastructure/systems/system_2/bmc -o ipaddress=192.168.56.109 username=root password_key=key-for-root
litp create -t disk -p /infrastructure/systems/system_2/disks/disk0 -o name=hd0 size=50G bootable=true uuid="ATA_VBOX_HARDDISK_VB5f76ef2a-ad21952b"

# Storage profile for nodes
litp create -t storage-profile -p /infrastructure/storage/storage_profiles/profile_1
litp create -t volume-group -p /infrastructure/storage/storage_profiles/profile_1/volume_groups/vg1 -o volume_group_name="vg_root"
litp create -t file-system -p /infrastructure/storage/storage_profiles/profile_1/volume_groups/vg1/file_systems/root -o type=ext4 mount_point=/ size=16G
litp create -t file-system -p /infrastructure/storage/storage_profiles/profile_1/volume_groups/vg1/file_systems/swap -o type=swap mount_point=swap size=2G
litp create -t physical-device -p /infrastructure/storage/storage_profiles/profile_1/volume_groups/vg1/physical_devices/internal -o device_name=hd0

# Setup cluster
litp create -t deployment -p /deployments/local_vm
litp create -t cluster -p /deployments/local_vm/clusters/cluster1
