# 실행

>syntax : deauth-attack \<interface\> \<ap mac\> [\<station mac\> [-auth]]

>sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB

# 설명
`ap mac`만 명시되는 경우에는 AP broadcast frame을 발생시킨다.


`station mac`까지 명시되는 경우에는 AP unicast, Station unicast frame을 발생시킨다.

`-auth` 옵션이 주어지면 deauthentication이 아닌 authentication으로 공격한다