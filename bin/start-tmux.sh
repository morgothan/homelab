#!/bin/bash

SESS="remote"

tmux has-session -t $SESS 2>/dev/null

if [ $? != 0 ]; then
#if [ $? = 0 ]; then #uncomment to test if new feature works on existing instance
# cut up the screen into 4 panes 
       tmux new-session -d -s $SESS -n "#H"
       tmux split-window -h
       tmux split-window -v
       tmux select-pane -t 0
       tmux split-window -v
       tmux select-pane -t 0

#set up default environment. 
# top left do nothing
#      tmux send-keys -t 0 "" C-m
       tmux select-pane -t 0 -T "#H"
# bottom left 
       tmux send-keys -t 1 "ssh sketchy-nas" C-m
       tmux select-pane -t 1 -T "#H"
# top right ssh into proxmox
       tmux send-keys -t 2 "ssh pve" C-m
       tmux send-keys -t 2 "btop -u 5000" C-m
       tmux select-pane -t 2 -T PVE      
# bottom right ssh into StorageMcStorageFace
#       tmux send-keys -t 3 "docker run --rm -it browsh/browsh" C-m
       tmux select-pane -t 3 -T "#H"
# set the names on the pabe bottoms       
       tmux set -g pane-border-status bottom
fi

tmux attach-session -t $SESS
