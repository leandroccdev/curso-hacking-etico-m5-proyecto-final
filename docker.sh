#!/usr/bin/bash
# Description
#   Handles the run and clean of container
#
# Ubuntu noble
image="flc-scanner"
container="c-${image}"
host_report_shared_folder=$(pwd)"/reportes"
container_report_shared_folder="/opt/flc-scanner/reportes"

# Functions
# -----------------------------------------------------------------------------
function docker_clean {
#<
    container_id=$(docker ps -aq -f name=^"$container")
    image_id=$(docker image ls -q "$image")
    [[ -n $container_id ]] && docker rm $container_id
    [[ -n $image_id ]] && docker image rm $image_id
#>
}

function docker_run {
#<
    # todo: do the pull conditionally
    docker pull ubuntu:noble
    docker_clean
    docker build -t $image .
    docker run --name $container \
        -v "${host_report_shared_folder}:${container_report_shared_folder}" \
        $image
#>
}

function docker_run_it {
#<
    # todo: do the pull conditionally
    docker pull ubuntu:noble
    docker_clean
    docker build -t $image .
    docker run --name $container \
        -v "${host_report_shared_folder}:${container_report_shared_folder}" \
        -it $image bash
#>
}
# -----------------------------------------------------------------------------

# Process options [run|clean]
case $1 in
    "run") docker_run;;
    "runit") docker_run_it;;
    "clean") docker_clean;;
    *) echo "$0 [run|clean]";;
esac
