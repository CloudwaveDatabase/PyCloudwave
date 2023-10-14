import time

import pycloudwave


class DB_Operate:

    def __init__(self,
                 host,
                 user,
                 passwd,
                 db,
                 port=1978
                 ):
        self.host = host
        self.port = port
        self.user = user
        self.passwd = passwd
        self.db = db

        # 连接数据库
        self.conn = self.connect_db()


    # 连接数据库
    def connect_db(self):
        try:
            # 连接数据库
            self.conn = pycloudwave.Connection(host=self.host,
                                               user=self.user,
                                               password=self.passwd,
                                               db=self.db,
                                               port=self.port
                                               )

            # 获取游标
            self.cur = self.conn.cursor()
            # 没有异常,connect_flag为0
            self.connect_flag = 0
        except Exception as e:
            print(e)
            self.connect_flag = 1

    # 创建数据库表
    def create_db(self, ):
        create_userinfo_table = """
        CREATE TABLE test.userinfo(
            id integer primary key,
            name varchar(16),
            addr varchar(64),
            birth date
        )
        """
        r = self.cur.execute(create_userinfo_table)
#        self.conn.commit()
        return r

    # 插入单条数据
    def insert_data(self, data):
        r = -1
        try:
            sql = "insert into test.userinfo values(%s, %s, %s, %s)"
            r = self.cur.execute(sql, data)
        except:
            self.conn.rollback()
        return r

    # 插入多条数据
    def insert_datas(self, datas):
        r = -1
        try:
            sql = "insert into test.userinfo values(%s, %s, %s, %s)"
            r = self.cur.executemany(sql, datas)
#            self.conn.commit()
        except:
            self.conn.rollback()
        return r

    # 修改数据
    def update_data(self, tablename, set, where):
        r = -1
        try:
            sql = "update " + tablename + " set " + set + " where " + where
            r = self.cur.execute(sql)
#            self.conn.commit()
        except:
            self.conn.rollback()
        return r

    # 查询单条数据
    def select_data(self, tablename, where):
        sql = "select * from " + tablename + " where " + where
        self.cur.execute(sql)
        r = self.cur.fetchone()
        return r

    # 查询多条数据
    def select_datas(self, tablename, where):
        sql = "select * from " + tablename + " where " + where
        self.cur.execute(sql)
        r = self.cur.fetchall()
        return r

    # 删除数据
    def delete_data(self, tablename, where):
        sql = "delete from " + tablename + " where " + where
        r = self.cur.execute(sql)
        return r

    # 删除数据库表
    def remove_db(self, tablename):
        sql = "drop table if exists " + tablename
        r = self.cur.execute(sql)
        return r

    # 关闭游标及数据库连接
    def close_db(self):
        self.cur.close()
        self.conn.close()

    def test(self):
        # SQL 查询语句
        sql = "SELECT * FROM test.userinfo WHERE addr = \'北京\'"
        try:
            # 执行SQL语句
            self.cur.execute(sql)
            # 获取所有记录列表
            results = self.cur.fetchall()
            for row in results:
                id = row[0]
                name = row[1]
                addr = row[2]
                birth = row[3]
                #打印结果
                print ("id=%s,name=%s,addr=%s,birth=%s" % \
                    (id, name, addr, birth))
        except:
            print ("Error: unable to fetch data")




my_host = "127.0.0.1"
my_port = 1978
my_db = "WEITEST"
my_user = "system"
my_passwd = "CHANGEME"

# 连接数据库
db = DB_Operate(my_host, my_user, my_passwd, my_db)

r = db.remove_db('test.userinfo')
print("删除库表（如果存在）：", r)

r = db.create_db()
print("创建库表：", r)

data = [10,'张三','上海', '2001-02-03']
r = db.insert_data(data)
print("插入记录数：", r)

datas = [[20, '李四', '北京', '2002-03-04'],
        [21, '王五', '南京', '2002-03-05'],
        [22, '赵六', '广州', '2002-04-06']]
r = db.insert_datas(datas)
print("插入记录数：", r)

r = db.update_data('test.userinfo', "addr=\'北京\'", "name=\'张三\'")
print("修改记录数：", r)

r = db.select_data('test.userinfo', 'id=21')
print("检索单条记录：", r)

r = db.select_datas('test.userinfo', "addr=\'北京\'")
print("检索多条记录：", r)

db.test()

r = db.delete_data('test.userinfo', "id>=20")
print("删除记录数：", r)

r = db.remove_db('test.userinfo')
print("删除库表：", r)

# 关闭游标及数据库连接
db.close_db
