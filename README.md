# 시놀로지 무작위 대입 접근 아이피 차단

시놀로지 사용중 접근하여 무작위 대입을 하는 IP 차단을 위해 만들었습니다.

## 프로세스
1. 접근 로그 실패 이력을 찾음
2. 실패 이력 중 허용된 사용자 여부를 체크함
3. 허용되지 않은 사용자의 실패 아이피를 지정한 일자 만큼 차단시킴
4. 단, 내부 아이피는 차단 안함, 한번 실패해도 차단

## 파일 설치
* 접근 가능한 임의의 폴더에 소스를 받음
* .env.example 파일을 .env 로 복사하여 필요한 정보를 넣어 세팅
  * BLOCK_EXPIRE_DAY 블럭 기간 : 단위 일, 0 으로 하면 항상
  * EXCEPT_IP_LIST 차단 예외 아이피 : , 로 구분하여 띄어쓰기 없이 입력

## 시놀로지 세팅
* 제어판 > 작업 스케줄러 에서
  * 생성 > 예약된 작업 > 사용자 정의 스크립트
  * 사용자는 root
  * 스케줄은 매일
  * 시간 : 주기 5분, 첫 실행시간 00, 종료시간 23:55
  * 아래의 스크립트를 넣음
```
/usr/bin/env python3 /소스코드가 저장된 폴더/ip_block.py
```