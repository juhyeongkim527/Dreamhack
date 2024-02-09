# 배열(Array)과 포인터(Pointer)의 차이

## 배열
1. 배열은 메모리에 index에 해당하는 데이터를 연속적으로 바로 저장한다.
2. 배열의 index가 가리키는 값을 변경할 수 있다.
3. 배열의 주소를 바꿀 수는 없다. (상수 포인터인 `char* const ptr`와 같은 의미, 그렇다고 둘이 같은 자료형인 것은 아님)
   
   **`ptr = arr;`은 가능하지만, `arr=ptr;`은 불가능**
   
## 포인터
1. 포인터는 메모리에 주소 값을 저장한다. (배열로 치면 index의 데이터를 바로 저장하는 것이 아닌 index의 데이터가 위치하는 주소를 저장함)
2. 포인터를 배열처럼 사용할 수 있지만, char형의 경우는 예외적으로 literal을 사용하기 때문에 index값 변경 불가 (`const char[]`와 같은 의미, 그렇다고 둘이 같은 자료형인 것은 아님)

**포인터와 배열은 같은 자료형이 아니다**

## 예제 1
``` 
1 #include<stdio.h>
2 #include<stdlib.h>
3
4 int main(){
5     char arr_str[] = "asdds";
6     char* ptr_str = "asdds";
7     arr_str[1]='d'; // valid
8     ptr_str[1]='d'; // invalid
9
10     printf("arr:%s \nptr:%s",arr_str,ptr_str);
11     return 0;
12}
```
char형 포인터는 literal의 주소를 저장하기 때문에, index에 접근하여 값 변경 불가능(char이외의 자료형은 literal이 아니므로 가능)
## 예제 2
```
char arr_str[] = "asd";
char arr_str[] = {'a','s','d','\0'};
```
위 두 변수는 같은 의미이지만,

```
char *ptr_str = "asd";
char *ptr_str = {'a','s','d','\0'}; // invalid
```
위 두 변수는 다른 의미이다. 포인터는 "asd" 문자열을 배열로 저장하는 것이 아니라 literal의 주소를 가져오기 때문이다.
따라서, 포인터로 string을 선언하면, 예제 1의 8번째 줄 처럼 문자의 일부를 교체할 수 없다.
