source /home/bronson/.gdbinit-gef.py
#source ~/peda/peda.py
#source ~/Pwngdb/pwngdb.py
source ~/Pwngdb/angelheap/gdbinit.py

define hook-run
python
import angelheap
angelheap.init_angelheap()
end
end

source ~/.d2d.py

