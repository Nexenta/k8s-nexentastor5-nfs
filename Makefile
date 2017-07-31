# Copyright 2016 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


IMAGE=quay.io/alexey_khodos/nexentastor5-nfs-provisioner
$(eval BRANCH=$(shell git rev-parse --abbrev-ref HEAD))
ifeq ($(BRANCH),master)
        TAG=latest
else
		TAG=$(BRANCH)
endif


all: clean image clean


.PHONY: image
image: nexentastor5-nfs-provisioner
	@docker build -t $(IMAGE):$(TAG) -f Dockerfile .

.PHONY: nexentastor5-nfs-provisioner
nexentastor5-nfs-provisioner:
	@echo "### docker build: builder image"
	@docker build  --build-arg BRANCH=$(BRANCH) -q -t builder -f Dockerfile.dev .
	@echo "### extract binary"
	@docker create --name tmp builder
	@docker start -i tmp
	@mkdir -p bin
	@docker cp tmp:/go/bin/nexentastor5-nfs-provisioner bin/
	@docker rm -vf tmp || true
	@docker rmi builder || true

.PHONY: clean
clean:
	@rm -rf bin nexentastor5-nfs-provisioner
	@docker rm -vf tmp || true
	@docker rmi builder || true

.PHONY: push
push:
	@echo "### push ${IMAGE}:${TAG}"
	@docker push ${IMAGE}:${TAG}
