# Installation and examples.
Clone this repository
```console
git clone https://github.com/Nexenta/k8s-nexentastor5-nfs.git && cd k8s-nexentastor5-nfs
```

## RBAC
```console
$ kubectl create -f serviceaccount.yaml
$ kubectl create -f clusterrole.yaml
$ kubectl create -f clusterrolebinding.yaml
$ kubectl patch deployment nexentastor5-nfs-provisioner -p '{"spec":{"template":{"spec":{"serviceAccount":"nexentastor5-provisioner"}}}}'
```

Configure environment variables in deployment.yaml according to your NexentaStor setup.
Create deployment and storage class.
```console
$ kubectl create -f deployment.yaml
$ kubectl create -f class.yaml
```

Check if the provisioner pod is running.
```console
$ kubectl get po
nexentastor5-nfs-provisioner-2310907426-jcv44   1/1       Running   0          11m
```

If the output says `Running` - you are ready to create PVCs and Pods.
You can use `claim.yaml` and `test-pod.yaml` to verify everything is working.
```console
$ kubectl create -f claim.yaml
$ kubectl create -f test-pod.yaml

```

Log in to the pod and verify that test file was created:
```console
$ kubectl exec -it test-pod sh
$ ls /mnt
SUCCESS
/ # df -h
Filesystem                Size      Used Available Use% Mounted on
overlay                 165.2G     13.7G    143.1G   9% /
tmpfs                    15.7G         0     15.7G   0% /dev
tmpfs                    15.7G         0     15.7G   0% /sys/fs/cgroup
10.3.1.1:/data1/kubernetes/pvc-eea600b1-68f1-11e7-90d2-12430bf7c5c9
                        951.5G         0    951.5G   0% /mnt
/dev/sda1               165.2G     13.7G    143.1G   9% /dev/termination-log
/dev/sda1               165.2G     13.7G    143.1G   9% /etc/resolv.conf
/dev/sda1               165.2G     13.7G    143.1G   9% /etc/hostname
/dev/sda1               165.2G     13.7G    143.1G   9% /etc/hosts
shm                      64.0M         0     64.0M   0% /dev/shm
tmpfs                    15.7G     12.0K     15.7G   0% /var/run/secrets/kubernetes.io/serviceaccount
tmpfs                    15.7G         0     15.7G   0% /proc/kcore
tmpfs                    15.7G         0     15.7G   0% /proc/timer_list
tmpfs                    15.7G         0     15.7G   0% /proc/timer_stats
tmpfs                    15.7G         0     15.7G   0% /proc/sched_debug

```

# Building the image.
Build the image from code ONLY when you have reasons for it.
Otherwise ignore this part and use the image from quay.io repository.
```console
git clone https://github.com/Nexenta/k8s-nexentastor5-nfs.git && cd k8s-nexentastor5-nfs
make
```
