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

## docker build

Dockerfile을 사용하여 **도커 이미지를 생성**하는 명령어이다.

- `docker build [옵션] <경로>`
- `docker build -t <이미지명:태그> <경로>`

여기서 **태그**는 우리가 위에서 보았듯이 하나의 이미지에 대한 여러 버전을 지정하기 위한 별명과 같다.

### Example

- `docker build .` : 현재 디렉토리에 있는 Dockerfile로 이미지 생성
- `docker build -t my-image .` : 현재 디렉토리에 있는 Dockerfile로 ‘my-image:latest’ 라는 태그를 가진 이미지 생성

## docker images

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

## docker run

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
