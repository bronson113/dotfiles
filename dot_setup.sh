#!/bin/bash

# get the repository
git clone --bare https://github.com/bronson113/dotfiles.git $HOME/.cfg

# run git within the context
function dotconfig {
    /usr/bin/git --git-dir=$HOME/.cfg/ --work-tree=$HOME $@
}
mkdir -p .config-backup
dotconfig checkout
# update the files
if [ $? = 0 ]; then
    echo "Checked out config.";
else
    echo "Backing up pre-existing dot files.";
    dotconfig checkout 2>&1 | egrep "\s+\." | awk {'print $1'} | xargs -I{} mv {} .config-backup/{}
fi;
dotconfig checkout
dotconfig config status.showUntrackedFiles no

# clone sub modules (can't automate due to bare repo)
git clone https://github.com/gpakosz/.tmux.git
git clone https://github.com/scwuaptx/Pwngdb.git
git clone https://github.com/bronson113/mktmpdir.git


# setup vim
curl -fLo ~/.vim/autoload/plug.vim --create-dirs https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim
vim +PlugUpgrade +PlugUpdate +PlugInstall +q


