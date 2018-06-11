#!/bin/bash

# Install python dependencies, ideally you should be using virtualenvs
pip install -r requirements.txt

# Install ripgrep: https://github.com/BurntSushi/ripgrep
curl -LO https://github.com/BurntSushi/ripgrep/releases/download/0.8.1/ripgrep_0.8.1_amd64.deb
sudo dpkg -i ripgrep_0.8.1_amd64.deb
rm ripgrep_0.8.1_amd64.deb

# Inform people about the ODM
echo
echo "All binary dependencies have been installed"
echo "However, in order to use this tool fully you need the Crunchbase ODM"
echo "If you work for SRA, then just ask for it. If not, get it yourself"
echo

