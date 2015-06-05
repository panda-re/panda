Vagrant.configure(2) do |config|

    # Setting proxy configurations for the host box. This also sets common proxy settings
    # and files for other applications, such as apt-get/yum
    if Vagrant.has_plugin?("vagrant-proxyconf")
        config.proxy.http = "http://140.102.211.9:3128"
        config.proxy.https = "http://140.102.211.9:3128"
        config.proxy.no_proxy = "localhost,127.0.0.1,*.draper.com"
    end

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
