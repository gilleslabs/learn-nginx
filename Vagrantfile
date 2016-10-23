# -*- mode: ruby -*-
# vi: set ft=ruby :

################################################################################################################
#                                                                                                              #
# Vagrantfile for provisioning ready-to-go nginx VM.#
#                                                                                                              #
# Author: Gilles Tosi                                                                                          #
#                                                                                                              #
# The up-to-date version and associated dependencies/project documentation is available at:                    #
#                                                                                                              #
# https://github.com/gilleslabs/learn-nginx                                                                    #
#                                                                                                              #
################################################################################################################

Vagrant.configure(2) do |config|

	config.vm.define "nginx" do |nginx|
        nginx.vm.box = "ubuntu/trusty64"
			config.vm.provider "virtualbox" do |v|
				v.cpus = 2
				v.memory = 2048
			end
        nginx.vm.network "private_network", ip: "192.168.99.60"
		nginx.vm.provision :shell, path: "provision.sh"
    end
end