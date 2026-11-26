# QEMU for infra/testvm/testvm.sh: the test VM runs in this container, so the host needs only Docker and /dev/kvm.
FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils genisoimage \
 && apt-get clean
