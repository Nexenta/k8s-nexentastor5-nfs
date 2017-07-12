You must extract the files in you gopath. I used #GOPATH/nexenta.

After you setup you go environment someone needs to issue:

# make image

# kubectl create –f class.yaml

# kubectl create –f clusterrole.yaml

# kubectl create –f clusterrolebinding.yaml

# kubectl create –f serviceaccount.yaml

Check variable in pod.yaml and create a pool with the name give in pod.yaml NEXENTA_HOSTPOOL on the nexenta-stor (I used nexenta fusion but I guess it is as well possible through ssh/rest)

# kubectl create –f pod.yaml


You should see:

po/nexenta-stor-provisioner   1/1       Running   0



Create a claim:

# kubectl create –f claim.yaml

Start a pod mounting the nfs

# kubectl create –f test-pod.yaml



That’s it! You should see the pod started and mounting the PV:

enikher@k8s-2:~/nexenta$ kubectl exec -it test-pod sh

/ # df -h

Filesystem                Size      Used Available Use% Mounted on
none                     86.0G     13.1G     68.6G  16% /
tmpfs                     5.9G         0      5.9G   0% /dev
tmpfs                     5.9G         0      5.9G   0% /sys/fs/cgroup
192.168.122.218:/nfs/pvc-fc321091-4794-11e7-89b4-5254006bdf84
                          1.0M         0      1.0M   0% /mnt
/dev/mapper/ubuntu--golden--vg-root
                         86.0G     13.1G     68.6G  16% /dev/termination-log
/dev/mapper/ubuntu--golden--vg-root
                         86.0G     13.1G     68.6G  16% /etc/resolv.conf
/dev/mapper/ubuntu--golden--vg-root
                         86.0G     13.1G     68.6G  16% /etc/hostname
/dev/mapper/ubuntu--golden--vg-root
                         86.0G     13.1G     68.6G  16% /etc/hosts
shm                      64.0M         0     64.0M   0% /dev/shm
tmpfs                     5.9G     12.0K      5.9G   0% /var/run/secrets/kubernetes.io/serviceaccount
tmpfs                     5.9G         0      5.9G   0% /proc/kcore
tmpfs                     5.9G         0      5.9G   0% /proc/timer_list
tmpfs                     5.9G         0      5.9G   0% /proc/timer_stats
tmpfs                     5.9G         0      5.9G   0% /proc/sched_debug
tmpfs                     5.9G         0      5.9G   0% /sys/firmware
/ #