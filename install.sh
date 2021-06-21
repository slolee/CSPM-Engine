# Python 경로 주의!!!
# 파이썬경로 못찾으면 src/main/java/com/ch4njun/cspm/demo/constant/Path.java 파일 수정해야함.

# 파이썬 라이브러리 설치
pip3 install datetime pytz boto3 pymysql maya

# 자바 설치
wget https://download.java.net/java/GA/jdk15.0.2/0d1cfde4252546c6931946de8db48ee2/7/GPL/openjdk-15.0.2_linux-x64_bin.tar.gz
tar -xzf openjdk-15.0.2_linux-x64_bin.tar.gz
rm -rf openjdk-15.0.2_linux-x64_bin.tar.gz
echo 'export JAVA_HOME=/home/ec2-user/jdk-15.0.2' >> ~/.bashrc
source ~/.bashrc

sudo yum -y install git
git clone https://github.com/slolee/CSPM-Engine
cd CSPM-Engine

# Script로 인자받아서 하면될듯?
# EX)  ./script ch4njun cks14579! 127.0.0.1
sed -i 's/\[ID\]/$1/g' src/main/resources/application.yml
sed -i 's/\[PW\]/$2/g' src/main/resources/application.yml
sed -i 's/\[IP\]/$3/g' src/main/resources/application.yml
sed -i 's/\[ID\]/$1/g' src/main/resources/engine/common/db.py
sed -i 's/\[PW\]/$2/g' src/main/resources/engine/common/db.py
sed -i 's/\[IP\]/$3/g' src/main/resources/engine/common/db.py
