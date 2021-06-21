pip3 install datetime pytz boto3 pymysql maya

wget https://download.java.net/java/GA/jdk15.0.2/0d1cfde4252546c6931946de8db48ee2/7/GPL/openjdk-15.0.2_linux-x64_bin.tar.gz + "/r"
tar -xzf openjdk-15.0.2_linux-x64_bin.tar.gz
rm -rf openjdk-15.0.2_linux-x64_bin.tar.gz
echo 'export JAVA_HOME=/home/ec2-user/jdk-15.0.2' >> ~/.bashrc
source ~/.bashrc

sed -i 's/\[ID\]/'$1'/g' src/main/resources/application.yml
sed -i 's/\[PW\]/'$2'/g' src/main/resources/application.yml
sed -i 's/\[IP\]/'$3'/g' src/main/resources/application.yml
sed -i 's/\[ID\]/'$1'/g' src/main/resources/engine/common/db.py
sed -i 's/\[PW\]/'$2'/g' src/main/resources/engine/common/db.py
sed -i 's/\[IP\]/'$3'/g' src/main/resources/engine/common/db.py
