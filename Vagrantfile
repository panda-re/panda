Vagrant.configure(2) do |config|
    config.vm.define "developer" do |dev|
        # Specify a base virtual machine that is based on Ubuntu Trusty Tahr
        dev.vm.box = "ubuntu/trusty64"

        # Setup a static IP to allow both vagrant boxes to know where 
        # to contact each other. This will allow communication between the
        # web developer and the logging server.
        dev.vm.network "private_network", ip: "192.168.86.100"

        # Specify the provisioning script that will be used in order to 
        # install the necessary files needed for this vagrant box
        dev.vm.provision "shell" do |s|
            s.path = "provision.sh"
            s.privileged = false
        end
        
        # Change the default client vagrant box folder to point to the 
        # client directory within the project. This will allow separation between
        # client and server folders.
        # dev.vm.synced_folder "client/", "/vagrant"

        # Host configuration: Set specific requirements for the host to
        # provide the Guest Box to use.
        dev.vm.provider :virtualbox do |vb|
            vb.customize ["modifyvm", :id, "--cpus", "4", "--memory", "2048"]
        end
    end
end
