# Docker란 ?

**도커(Docker)** 는 **컨테이너를 만들고, 실행하고, 배포할 수 있는 가상화 플랫폼**이다.

도커의 컨테이너란, 가상의 환경이 구축되어 있는 하나의 박스를 말한다. 

VirtualBox 등의 가상 머신으로 하나의 운영체제 위에 다른 운영체제 환경을 구축하는 것과 유사하지만,\
**도커 컨테이너는 1. 새로운 운영체제 환경을 구축할 필요 없이 2. 하나의 분리된 프로세스처럼 작동하여 더 가볍다.** 쉽게 말하면 특정한 환경을 구성하기 위해 만들어진 가상의 공간이다.

도커는 가상머신에 비해 설치하는 시간과 과정이 매우 단순하고, 간편하게 문제 환경을 재현할 수 있기 때문에 워게임에서 도커 이미지를 만들고 컨테이너를 실행할 수 있는 Dockerfile을 동시에 제공하는 경우가 많다.

## Docker Image

도커 이미지는 **도커 컨테이너의 전 단계**로, **컨테이너를 생성하고 실행하기 위한 모든 것**을 포함한다. 자신만의 이미지를 만들거나 다른 사람이 만든 이미지를 사용할 수도 있다.
- EX) 컨테이너 생성에 필요한 파일, 환경 변수, 명령어 등과 파일 시스템 

이미지를 생성하려면 **Dockerfile을 작성**하고 **이미지를 빌드**해야 한다. Dockerfile은 이미지를 빌드하는 데 단계적으로 필요한 명령어가 있는 파일.

도커 이미지에는 **태그(Tag)** 를 붙일 수 있는데, 태그를 붙이는 것은 하나의 이미지에 여러 개의 별명을 붙여 주는 것과 같다. \
주로 **이미지의 버전을 지정하기 위해 사용**한다.

## Docker Container

도커 컨테이너는 **도커 이미지로부터 만들어진 실행 가능한 인스턴스**이다.\
다르게 말하면, **실행 중인 이미지**를 컨테이너라고 한다. 컨테이너는 도커 이미지와 사용자가 컨테이너를 시작할 때 작성하는 옵션에 의해 정의되고, 컨테이너를 실행하는 동안은 분리된 파일 시스템을 사용한다.

# 도커 명령어

## `docker build`

Dockerfile을 사용하여 **도커 이미지를 생성**하는 명령어이다.

- `docker build [옵션] <경로>`
- `docker build -t <이미지명:태그> <경로>`

여기서 **태그**는 우리가 위에서 보았듯이 하나의 이미지에 대한 여러 버전을 지정하기 위한 별명과 같다.

### Example

- `docker build .` : 현재 디렉토리에 있는 Dockerfile로 이미지 생성
- `docker build -t my-image .` : 현재 디렉토리에 있는 Dockerfile로 ‘my-image:latest’ 라는 태그를 가진 이미지 생성

## `docker images`

**도커 이미지 목록**을 출력하는 명렁어이다.

아래는 미리 준비된 Dockerfile을 이용해서 docker build 명령어로 이미지를 빌드한 후, docker images 명령어로 출력하는 모습이다.

```
user@user-VirtualBox:~/Desktop/ex-docker$ docker build .
[+] Building 27.1s (17/17) FINISHED                                             
 => [internal] load build definition from Dockerfile                       0.0s                                         
 => ...생략...
 => exporting to image                                                     0.0s
 => => exporting layers                                                    0.0s
 => => writing image sha256:08a83756c396b9ca5d83735153cf0176056fb23c3eb3c  0.0s
user@user-VirtualBox:~/Desktop/ex-docker$ docker images
REPOSITORY   TAG       IMAGE ID       CREATED         SIZE
<none>       <none>    9d201c4de2b6   2 minutes ago   122MB

user@user-VirtualBox:~/Desktop/ex-docker$ docker build -t my-image:1 .
[+] Building 0.8s (17/17) FINISHED                                              
 => ...생략...
 => exporting to image                                                     0.0s
 => => exporting layers                                                    0.0s
 => => writing image sha256:9d201c4de2b62519383058265e31669b167c422502643  0.0s
 => => naming to docker.io/library/my-image:1                              0.0s

user@user-VirtualBox:~/Desktop/ex-docker$ docker images
REPOSITORY   TAG       IMAGE ID       CREATED         SIZE
my-image     1         9d201c4de2b6   4 minutes ago   122MB
```

## `docker run`

생성된 도커 이미지로 **컨테이너를 생성하고 동시에 실행**하는 명령어이다.

- `docker run [옵션] <이미지명|ID> [명령어]`

- `docker run -p <호스트 PORT>:<컨테이너 PORT> <이미지명|ID>`

`-p` 옵션은 도커 컨테이너의 포트와 호스트의 포트를 매핑하는 옵션이다. 컨테이너에서 리슨하고 있는 포트를 호스트의 특정 포트로 접속할 수 있도록 한다.

### Example

- `docker run -it my-image:1 /bin/bash` : `my-image:1` 이미지로 컨테이너를 생성하고 실행하여 **bash 셸**(`/bin/bash`) 열기

```
user@user-VirtualBox:~/Desktop/ex-docker$ docker run -it my-image:1 /bin/bash

chall@852bb2be037c:~$
```

## `docker ps`

실행 중인 컨테이너 목록을 출력하는 명령어이다.

- `docker ps -a` : `-a` 옵션은 실행중인 컨테이너 뿐만 아니라 종료된 컨테이너까지 모두 출력하는 옵션이다.

### Example

컨테이너를 실행한 상태로 다른 터미널 창을 열어 `docker ps`를 입력하면 아래와 같이 실행 중인 컨테이너 목록이 출력된다.

![image](https://github.com/juhyeongkim527/Dreamhack/assets/138116436/23449a6e-11df-45f5-ab2a-d393efb952a8)

컨테이너 안에서 `exit` 명령어를 실행하여 컨테이너를 종료한 후 `docker ps`를 입력하면 컨테이너가 출력되지 않고, `docker ps -a`를 입력하면 종료된 컨테이너까지 출력된다.

![image](https://github.com/juhyeongkim527/Dreamhack/assets/138116436/caabb2f5-d6f7-4ae8-8091-7cf6f809201b)

## `docker create`, `docker start`

`docker run` 명령어는 생성된 이미지에서 컨테이너를 생성하는 동시에 실행까지 하는 명령어였다면, `docker create`와 `docker start`는 생성과 실행을 나눠서 하는 명령어이다. 여기에 `docker exec` 까지 실행하면 `docker run`의 모든 과정이 된다.

- `docker create [옵션] <이미지명|ID> [명령어]` : 도커 이미지 이름을 통해 컨테이너 생성
- `docker start [옵션] <컨테이너명|ID>` : 도커 컨테이너 이름을 통해 컨테이너 실행

### Example

```
user@user-VirtualBox:~$ docker images
REPOSITORY   TAG       IMAGE ID       CREATED       SIZE
my-image     1         9d201c4de2b6   2 hours ago   122MB

user@user-VirtualBox:~$ docker create my-image:1
eb01688504dc201d9f3a03bf3a27d84cdeafca4b2110766d52fc7551a7d9d05a
user@user-VirtualBox:~$ docker ps -a
CONTAINER ID   IMAGE        COMMAND                  CREATED         STATUS    PORTS     NAMES
eb01688504dc   my-image:1   "/bin/sh -c 'socat -…"   4 seconds ago   Created             priceless_meninsky

user@user-VirtualBox:~$ docker start eb01688504dc
eb01688504dc

user@user-VirtualBox:~$ docker ps
CONTAINER ID   IMAGE        COMMAND                  CREATED          STATUS         PORTS      NAMES
eb01688504dc   my-image:1   "/bin/sh -c 'socat -…"   19 seconds ago   Up 4 seconds   2222/tcp   priceless_meninsky
```

## `docker exec`

실행중인 컨테이너에 접속하여 명령을 수행하는 명령어이다. `docker run`과 유사하게 사용이 가능하지만 이미지를 통해 컨테이너를 생성하고 실행하는 것이 아닌 이미 실행중인 컨테이너에 접속하여 명령어를 실행하는 차이가 있다.

`docker create` -> `docker start` -> `docker exec`을 통해 컨테이너에 접속하여 명령을 수행할 수 있고 이는 `docker run`이 한번에 수행한다.

`docker exec [옵션] <컨테이너명|ID> [명령어]` 

### Example

`docker run`과 유사하게 `-it` 옵션으로 **bash 셸을 실행**할 수 있다.

➡️ `docker exec -it <컨테이너명|ID> /bin/bash` : 실행 중인 컨테이너에서 bash 셸 열기

```
user@user-VirtualBox:~$ docker exec -it eb01688504dc /bin/bash

chall@eb01688504dc:~$
```

## `docker stop`

실행 중인 컨테이너를 중단하는 명령어이다. 실행 중인 컨테이너 내부에서는 자신의 컨테이너를 중단하려면 `exit` 명령어를 이용해야 하고, 실행중인 외부 컨테이너를 중단시킬 때 해당 명령어를 사용한다.

## `docker pull`

레지스트리(Docker Hub)에 존재하는 **도커 이미지를 다운**받는 명령어이다.

`docker pull [옵션] <이미지명>`

### Example

- `docker pull ubuntu:18.04` : Docker hub에서 ubuntu:18.04 이미지를 다운받습니다.

```
user@user-VirtualBox:~$ docker pull ubuntu:18.04

18.04: Pulling from library/ubuntu
0c5227665c11: Pull complete 
Digest: sha256:8aa9c2798215f99544d1ce7439ea9c3a6dfd82de607da1cec3a8a2fae005931b
Status: Downloaded newer image for ubuntu:18.04
docker.io/library/ubuntu:18.04
```

## `docker rm`

**도커 컨테이너를 삭제**하는 명령어이다.

- `docker rm [옵션] <컨테이너명|ID>`

##  `docker rmi`

**도커 이미지를 삭제**하는 명령어이다.

- `docker rmi [옵션] <이미지명|ID>`

## `docker inspect`

도커 이미지 혹은 컨테이너의 자세한 정보를 출력하는 명령어이다.

- `docker inspect [옵션] <이미지 혹은 컨테이너명|ID>`

### Example

```
user@user-VirtualBox:~$ docker inspect ubuntu:18.04
[
    {
        "Id": "sha256:3941d3b032a8168d53508410a67baad120a563df67a7959565a30a1cb2114731",
        "RepoTags": [
            "ubuntu:18.04"
        ],
        "RepoDigests": [
            "ubuntu@sha256:8aa9c2798215f99544d1ce7439ea9c3a6dfd82de607da1cec3a8a2fae005931b"
        ],
        "Parent": "",
        "Comment": "",
        "Created": "2023-03-08T03:22:44.73196058Z",
        "Container": "ee3fcc8c88d3f3129f1236850de28a7eba0da7c548a7b23a6495905ebcf255ea",
        "ContainerConfig": {
            "Hostname": "ee3fcc8c88d3",
            "Domainname": "",
            "User": "",
            "AttachStdin": false,
            "AttachStdout": false,
            "AttachStderr": false,
            "Tty": false,
            "OpenStdin": false,
            "StdinOnce": false,
            "Env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            ],
            "Cmd": [
                "/bin/sh",
                "-c",
                "#(nop) ",
                "CMD [\"/bin/bash\"]"
            ],
            "Image": "sha256:b64649bc9d1a48300ec5a929146aa3c5ca80046f74c33aa5de65a7046f5177a6",
            "Volumes": null,
...
...
        "Architecture": "amd64",
        "Os": "linux",
        "Size": 63146040,
        "VirtualSize": 63146040,
        "GraphDriver": {
            "Data": {
                "MergedDir": "/var/lib/docker/overlay2/0fe24c66cfaad338ccd55946d7734702a3575513fb2e697b409d3194c95c7e62/merged",
                "UpperDir": "/var/lib/docker/overlay2/0fe24c66cfaad338ccd55946d7734702a3575513fb2e697b409d3194c95c7e62/diff",
                "WorkDir": "/var/lib/docker/overlay2/0fe24c66cfaad338ccd55946d7734702a3575513fb2e697b409d3194c95c7e62/work"
            },
            "Name": "overlay2"
        },
        "RootFS": {
            "Type": "layers",
            "Layers": [
                "sha256:b7e0fa7bfe7f9796f1268cca2e65a8bfb1e010277652cee9a9c9d077a83db3c4"
            ]
        },
        "Metadata": {
            "LastTagTime": "0001-01-01T00:00:00Z"
        }
    }
]
```
