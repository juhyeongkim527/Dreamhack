## 정리

- RELocation Read-Only(RELRO): 불필요한 데이터 영역에 쓰기 권한을 제거함.

- Partial RELRO: `.init_array`, `.fini_array` 등 여러 섹션에 쓰기 권한을 제거함. **Lazy binding을 사용**하므로 라이브러리 함수들의 GOT 엔트리는 쓰기가 가능함. **GOT Overwrite등의 공격으로 우회가 가능함.**

- Full RELRO: `.init_array`, `.fini_array` 뿐만 아니라 **GOT에도 쓰기 권한을 제거**함. **Lazy binding을 사용하지 않으며** 라이브러리 함수들의 주소는 바이너리가 로드되는 시점에 바인딩됨.   
libc의 malloc hook, free hook과 같은 함수 포인터를 조작하는 공격으로 우회할 수 있음. => **Hook Overwrite**
