Wireshark 기반의 프로토콜 메시지 분석기를 LUA 스크립트 언어를 사용하여 개발합니다. 

## Editor
Visual Studio Code
Test233
## LUA 스크립트 설치
1. 관리자 모드 CMD 창에서 아래 명령을 수행합니다. [LUA 스크립트 파일 이름] 부분에는 복사하려는 LUA 스크립트 파일명으로 대체합니다. 
33777
```
copy /Y ".\[LUA 스크립트 파일 이름].lua" "C:\Program Files\Wireshark\plugins\[LUA 스크립트 파일 이름].lua"
```

2. Wireshark 실행 시 자동 반영됩니다. 

3. Wireshark 실행 중이라면 Ctrl+Shift+L 입력 시 동적으로 적용됩니다. 
