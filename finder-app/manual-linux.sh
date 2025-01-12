#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.15.163
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-

if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p ${OUTDIR}

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}

    # TODO: Add your kernel build steps here
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}  mrproper
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}  defconfig
    # Please note that OpenSSL headers are required to compile the kernel.
    # Ubuntu: sudo apt install libssl-dev
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}  -j8
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}  -j8 modules
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}  -j8 dtbs

fi

echo "Adding the Image in outdir"
cp ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ${OUTDIR}

echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi

# TODO: Create necessary base directories

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
git clone git://busybox.net/busybox.git
    cd busybox
    git checkout ${BUSYBOX_VERSION}
    # TODO:  Configure busybox
else
    cd busybox
fi

# TODO: Make and install busybox
make distclean
make defconfig
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} -j8
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} CONFIG_PREFIX=${OUTDIR}/rootfs install

cd ${OUTDIR}/rootfs

echo "Library dependencies"
${CROSS_COMPILE}readelf -a bin/busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a bin/busybox | grep "Shared library"

# TODO: Add library dependencies to rootfs
mkdir -p lib{,64} || (echo "Failed to create lib directories in rootfs" && exit 1)

# gcc resides in bin/, so go 1 level up
ARM_TOOLCHAIN_PATH=$(dirname $(which ${CROSS_COMPILE}gcc))/..
TOOLCHAIN_LIBS="${ARM_TOOLCHAIN_PATH}/aarch64-none-linux-gnu/libc"

pushd $TOOLCHAIN_LIBS
cp lib/ld-linux-aarch64.so.1 ${OUTDIR}/rootfs/lib/
cd lib64
cp libc.so.6 libm.so.6 libresolv.so.2 ${OUTDIR}/rootfs/lib64
popd

# TODO: Make device nodes
# For some reason mknod dev/<device> does not work on my system, while cd dev && mknod <device> works.
mkdir dev || (echo "Failed to create dev directory in rootfs" && exit 1)
cd dev
sudo mknod null -m 666 c 1 3
sudo mknod console -m 666 c 5 1
cd ..

# TODO: Clean and build the writer utility
cd $FINDER_APP_DIR
make clean
make CROSS_COMPILE=$CROSS_COMPILE

# TODO: Copy the finder related scripts and executables to the /home directory
# on the target rootfs

# TODO: Chown the root directory

# TODO: Create initramfs.cpio.gz
