#!/usr/bin/env python
import pycloudwave
import numpy as np
np.set_printoptions(suppress=True)

conn = pycloudwave.Connection(host="127.0.0.1", port=1978, user="system", passwd="CHANGEME", db="WEITEST")

r = conn.autocommit(False)
print("autocommit", r)

"""
r = conn.ping()
print("ping", r)

r = conn.commit()
print("commit", r)

r = conn.rollback()
print("rollback", r)
"""
cur = conn.cursor()

# r = conn.autocommit(True)
# sql = 'delete from weitest.user1 where id>1'
# r = cur.execute(sql)
# print("execute delete", r)
# r = conn.commit()
# print("commit", r)

# data = [[ 9011, 'mysql weitest1 user1', '男', '2022-03-20', -12345678901234567, 0.8787, '南京' ],
#     [ 902, 'mysql weitest1 user1', '男', '2022-03-20', -678901.78, 0.8787, '南京' ],
#     [903, 'mysql weitest1 user1', '男', '2022-03-20', 7234560, 0.8790, '南京']]
# sql = 'insert into weitest.user1 values (%s, %s, %s, %s, %s, %s, %s);'
# try:
#     r = cur.executemany(sql, data)
#     print("executemany", r)
#     r = conn.commit()
#     print("commit", r)
#     while True:
#         r = cur.fetchone()
#         if r is None:
#             break
#         print(r)
# except:
#     r = conn.rollback()
#     print("rollback", r)


# r = cur.execute("show tables;")
# print("DESC table", r)
# r = cur.fetchall()
# print("fetchall ", r)


"""
v = (149, "cloudwave weitest1 user3", "女3", "2023-03-20", 65.98, 0, "上海4", )
sql = 'insert into weitest.user1 (id, name, sex, birthday, d1, d2, address) values (%s, %s, %s, %s, %s, %s, %s)'
r = cur.execute(sql, v,)
print("execute insert", r)
"""

"""
sql = 'update weitest.user1 set  address=\'北京\' where id=112'
r = cur.execute(sql)
print("execute update", r)
"""

"""
sql = 'delete from weitest.user1 where id>1'
r = cur.execute(sql)
print("execute delete", r)
"""

"""
r = cur.execute("drop table weitest.user1")
print("drop table", r)
r = cur.fetchall()
print("fetchall ", r)
"""


r = cur.execute("SELECT * FROM weitest.user1")
print("execute select", r)

# r = cur.fetchmany()
# print("fetchmany ", r)

while True:
    r = cur.fetchone()
    if r is None:
        break
    print(r)

print(cur.description)
print()

for row in cur:
    print(row)

r = cur.close()
print("cur close", r)
r = conn.close()
print("conn close", r)

