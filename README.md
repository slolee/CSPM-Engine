# 프로젝트 소개
## CSPM 이란?
CSPM은 Cloud Security Posture Management의 약자로 클라우드에서 존재하는 설정 값, 구성요소와 같은 상태에서 발생할 수 있는 보안적 위험사항들을 자동으로 찾아내고 관리해주는 시스템을 말합니다.

이러한 시스템은 아래와 같은 기업에서 이용할 수 있습니다.
1. 온프레미스 환경에서 운영중인 서비스를 클라우드 환경으로 마이그레이션하려고 하는 기업.
1. 기존에 클라우드 환경에서 운영중인 서비스의 인프라에 대해 보안성 점검 및 관리를 하고자 하는 기업.
<br><br>
 
기본적인 시스템의 구조는 아래 이미지와 같습니다.

![1](https://user-images.githubusercontent.com/38906956/120291453-4761b700-c2fe-11eb-859d-a077daf18bc9.png)
<br><br>

이 프로젝트는 위 구조도에서 Engine Server에 해당합니다.
<br><br>

# Engine Server
## API List
Engine Server는 다음과 같은 API 항목을 제공합니다. (Swagger)

![2](https://user-images.githubusercontent.com/38906956/120291856-b93a0080-c2fe-11eb-9c3c-dcd4ddd5a045.png)
<i> 위 사진은 서버를 올린  http://[Engine-Server-IP]/swagger-ui/index.html 에서 확인 가능합니다.</i>
<br><br>

### <b>GET /assessment-results</b>
History Id, Resource Id, Result(Y, N, ?) 를 통해 점검 결과를 읽어옵니다.<br>
(모든 파라미터는 생략할 수 있고, 추가된 파라미터를 조합해 필터링한 결과를 )

<b>Request</b> : [GET] http://127.0.0.1:10831/assessment-results/?historyId=ch4njun&result=Y<br>
<b>Response</b> :
[
  {
    "accessKey": "string",
    "id": 0,
    "resourceId": "string",
    "resourceName": "string",
    "resourceType": "string",
    "service": "string",
    "tag": "string"
  }
]
<br><br>

### <b>GET /assessment-results/{id}</b>
Id(Primary Key) 를 통해 하나의 점검 결과를 읽어옵니다.

<b>Request</b> : [GET] http://127.0.0.1:10831/assessment-results/12<br>
<b>Response</b> :
{
    "accessKey": "string",
    "id": 0,
    "resourceId": "string",
    "resourceName": "string",
    "resourceType": "string",
    "service": "string",
    "tag": "string"
}
<br><br>

### <b>POST /assessment-results</b>
Request Body를 통해 History Id, Access Key, Secret Key, Region, Services 를 전달해 해당 계정에 대한 클라우드 점검 스크립트를 동작시킵니다.

엔진 서버의 파일 시스템에 포함되어 있는 점검 스크립트를 동작시키며 점검 결과는 연결되어있는 Database에 저장합니다.

<b>Request</b> : [POST] http://127.0.0.1:10831/assessment-results<br>
<b>Request Body</b> : 
{
  "accessKey": "string",
  "regionName": "string",
  "secretKey": "string"
}<br>
<b>Response</b> :
{
    "accessKey": "string",
    "id": 0,
    "resourceId": "string",
    "resourceName": "string",
    "resourceType": "string",
    "service": "string",
    "tag": "string"
}
<br><br>

### <b>PUT /assessment-results</b>
이미 점검이 완료된 결과를 수정합니다. 인터뷰 항목에 대해서 사용자가 코멘트와 함께 수정할 때 해당 API를 이용해 Database에 있는 값을 수정할 수 있습니다.

<b>Request</b> : [POST] http://127.0.0.1:10831/assessment-results<br>
<b>Request Body</b> : 
{
  "interview": true,
  "interviewContent": "string",
  "result": "string"
}<br>
<b>Response</b> :
{
  "accessKey": "string",
  "id": 0,
  "resourceId": "string",
  "resourceName": "string",
  "resourceType": "string",
  "service": "string",
  "tag": "string"
}
<br><br>

### <b>GET /histories/{historyId}</b>
History Id를 통해 하나의 History 정보를 읽어옵니다.

<b>Request</b> : [GET] http://127.0.0.1:10831/histories/ch4njun<br>
<b>Response</b> : 
{
  "historyId": "string",
  "status": "string"
}
<br><br>

### <b>DELETE /histories</b>
Request Body에 전달되는 History Id들을 삭제합니다. History Id를 삭제할 경우 해당 Id에 대한 점검결과(AssessmentResult)도 함께 삭제됩니다.

<b>Request</b> : [DELETE] http://127.0.0.1:10831/histories<br>
<b>Request Body</b> : 
{
  "accessKeys": [
    "string"
  ]
}<br>
<b>Response</b> : 200 OK
<br><br>

### <b>GET /resources</b>
파라미터로 전달되는 AccessKey, Service(IAM, EC2, ...) 를 통해 리소스 목록을 읽어옵니다.<br>
(파라미터 Service는 생략할 수 있습니다.)

<b>Request</b> : [GET] http://127.0.0.1:10831/resources?accessKey=ABCDEFG<br>
<b>Response</b> : 
[
  {
    "accessKey": "string",
    "id": 0,
    "resourceId": "string",
    "resourceName": "string",
    "resourceType": "string",
    "service": "string",
    "tag": "string"
  }
]
<br><br>

### <b>GET /resources/{id}</b>
Id(Primary Key)를 통해 하나의 Resource 목록을 읽어옵니다.

<b>Request</b> : [GET] http://127.0.0.1:10831/resources/12<br>
<b>Response</b> : 
{
  "accessKey": "string",
  "id": 0,
  "resourceId": "string",
  "resourceName": "string",
  "resourceType": "string",
  "service": "string",
  "tag": "string"
}
<br><br>

### <b>POST /resources</b>
Request Body를 통해 Access Key, Secret Key, Region 를 전달해 해당 계정에 대한 리소스 목록을 수집합니다.

엔진 서버의 파일 시스템에 포함되어 있는 리소스 스크립트를 동작시키며 수집한 리소스 목록은 연결되어있는 Database에 저장합니다.

<b>Request</b> : [POST] http://127.0.0.1:10831/resources<br>
<b>Request Body</b> : 
{
  "accessKey": "string",
  "regionName": "string",
  "secretKey": "string"
}<br>
<b>Response</b> : 
{
  "message": "string",
  "output": "string"
}
<br><br>

### <b>DELETE /resources</b>
Request Body에 전달되는 AccessKey들의 리소스 목록을 삭제합니다.

<b>Request</b> : [DELETE] http://127.0.0.1:10831/resources<br>
<b>Request Body</b> : 
{
  "accessKeys": [
    "string"
  ]
}<br>
<b>Response</b> : 200 OK
<br><br>
