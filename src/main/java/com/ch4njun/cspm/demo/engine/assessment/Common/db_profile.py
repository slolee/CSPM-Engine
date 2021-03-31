from Common.data import low_data
user = 'ch4njun'
passwd = 'cks14579'
host = 'ch4njun-script-db.ckjufvaxbvyp.ap-northeast-2.rds.amazonaws.com'
db = 'cspm'
charset = 'utf8'

import pymysql
conn = pymysql.connect(host=host, user=user, password=passwd, db=db, charset=charset)
cur = conn.cursor()

def execute_insert_sql(diagnosis_result):
    cur.execute('insert into assessment_result(history_id, service, chk_index, resource_name, resource_id, result, raw_data) values(%s, %s, %s, %s, %s, %s, %s)', diagnosis_result)
    conn.commit()
