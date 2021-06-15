import pymysql

def execute_insert_assessment_result_sql(assessment_result):
    global cur, conn
    cur.execute('insert into assessment_result(history_id, service, chk_index, resource_name, resource_id, result, raw_data) values(%s, %s, %s, %s, %s, %s, %s)', assessment_result)

def execute_insert_history_sql(history):
    global cur, conn
    cur.execute('insert into history(history_id, status) values(%s, %s)', history)

def execute_insert_resource_sql(resource):
    global cur, conn
    cur.execute('insert into resource(access_key, service, resource_type, resource_name, resource_id, tag) values(%s, %s, %s, %s, %s, %s)', resource)

def execute_select_history_sql(history_id):
    global cur
    cur.execute('select id from history where history_id = %s', history_id)
    return cur.fetchall()

def commit():
    global conn
    conn.commit()

user = 'ch4njun'
password = 'cks14579!'
host = 'terraform-20210615050925589900000001.ckjufvaxbvyp.ap-northeast-2.rds.amazonaws.com'
db = 'cspm'
charset = 'utf8'

conn = pymysql.connect(host=host, user=user, password=password, db=db, charset=charset)
cur = conn.cursor()
