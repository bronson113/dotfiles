# My dot files

Contains my configuration file for

- bash
- vim
- vim-plug
- template for pwntools
- tmux
- oh-my-tmux
- gdb
- gef
- binsync + decompiler to debugger
- git config

## Setup script

as user:
```bash
sudo apt update
sudo apt install -y curl git gdb vim-gtk3 tmux
cd
curl -Lks https://raw.githubusercontent.com/bronson113/dotfiles/master/dot_setup.sh | /bin/bash
source ~/.bashrc
```

as root:
```bash
apt update
apt install -y curl git gdb vim-gtk3 tmux
cd
curl -Lks https://raw.githubusercontent.com/bronson113/dotfiles/master/dot_setup.sh | /bin/bash
source ~/.bashrc
```

> vim-gtk3 provides clipboard support

## Backup Current Setting

use the backup script to backup all dotfile and tagged with the current time
```
~/backup.sh
```
