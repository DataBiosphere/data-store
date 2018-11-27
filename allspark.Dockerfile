# This is the build image for the DSS, intended for use with the allspark GitLab server
# It may be built and uploaded with the commands:
#   `docker login
#   `docker build -f allspark.Dockerfile -t {docker_username}/{tag_key}:{tag_value} .`
#   `docker push {docker_username}/{tag_key}:{tag_value}`
# For example,
#   `docker login
#   `docker build -f allspark.Dockerfile -t humancellatlas/dss-build-box .`
#   `docker push humancellatlas/dss-build-box`
#
# Now reference the image in .gitlab-ci.yml with the line:
#   `image: {docker_username}/{tag_key}:{tag_value}
#
# Please see Docker startup guide for additional info:
#   https://docs.docker.com/get-started/ 

FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update --quiet \
    && apt-get install --assume-yes --no-install-recommends \
        ca-certificates \
        build-essential \
        default-jre \
        gettext \
        git \
        httpie \
        jq \
        make \
        moreutils \
        python3-pip \
        python3.6-dev \
        unzip \
        wget \
        zlib1g-dev

RUN apt-get update --quiet

RUN python3 -m pip install --upgrade pip==10.0.1 
RUN python3 -m pip install virtualenv==16.0.0
RUN ln -s /usr/bin/python3.6 /usr/bin/python
RUN ln -s /usr/bin/pip3 /usr/bin/pip

RUN useradd -d /home/hca_cicd -ms /bin/bash -g root -G sudo hca_cicd
RUN mkdir /HumanCellAtlas && chown hca_cicd /HumanCellAtlas
USER hca_cicd
WORKDIR /home/hca_cicd

ENV PATH /home/hca_cicd/bin:${PATH}
RUN mkdir -p /home/hca_cicd/bin

ENV ES_VERSION 5.4.2
ENV DSS_TEST_ES_PATH=/home/hca_cicd/elasticsearch-${ES_VERSION}/bin/elasticsearch
RUN wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${ES_VERSION}.tar.gz \
    && tar -xzf elasticsearch-${ES_VERSION}.tar.gz -C /home/hca_cicd

RUN wget https://releases.hashicorp.com/terraform/0.11.10/terraform_0.11.10_linux_amd64.zip \
    && unzip terraform_0.11.10_linux_amd64.zip -d /home/hca_cicd/bin

# Address locale problem, see "Python 3 Surrogate Handling":
# http://click.pocoo.org/5/python3/
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8
