FROM alpine:3.6
COPY bin/nexentastor5-nfs-provisioner /
CMD ["/nexentastor5-nfs-provisioner"]
